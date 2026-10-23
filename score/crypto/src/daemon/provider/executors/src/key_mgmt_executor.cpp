/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

#include "score/crypto/src/daemon/provider/executors/key_mgmt_executor.hpp"

#include "score/crypto/src/daemon/key_management/interfaces/key_management_operations.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_types.hpp"
#include "score/crypto/src/daemon/provider/executors/key_mgmt_request_parser.hpp"

#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/mw/log/logging.h"

#include <string_view>

namespace score::crypto::daemon::provider::crypto_executor
{
namespace
{
constexpr std::string_view LOG_PREFIX = "[KEY_MGMT_EXEC] ";

namespace km_ops = key_management::operations;
namespace km_parse = key_mgmt_request_parser;
}  // namespace

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

KeyManagementExecutor::KeyManagementExecutor(std::shared_ptr<key_management::IKeyFactory> factory,
                                             std::shared_ptr<key_management::IKeySlotHandler> slot_handler,
                                             std::shared_ptr<key_management::KeyManagementService> service)
    : m_factory{std::move(factory)}, m_slot_handler{std::move(slot_handler)}, m_service{std::move(service)}
{
}

// ---------------------------------------------------------------------------
// Execute — top-level dispatch
// ---------------------------------------------------------------------------

Expected<common::ResponseParameters, score::crypto::daemon::common::DaemonErrorCode> KeyManagementExecutor::Execute(
    const KeyMgmtExecutionContext& ctx,
    const common::OperationIdentifier& operationId,
    common::RequestParameters& request)
{
    const auto action = operationId.operationAction;

    if (action == km_ops::KEY_GENERATE)
    {
        return HandleGenerate(ctx, request);
    }
    if (action == km_ops::KEY_LOAD)
    {
        return HandleLoad(ctx, request);
    }
    if (action == km_ops::KEY_IMPORT)
    {
        return HandleImport(ctx, request);
    }
    if (action == km_ops::KEY_EXPORT)
    {
        return HandleExport(ctx, request);
    }
    if (action == km_ops::KEY_GET_EXPORT_SIZE)
    {
        return HandleGetExportSize(ctx, request);
    }
    if (action == km_ops::KEY_RELEASE)
    {
        return HandleRelease(ctx.client_id, request);
    }
    if (action == km_ops::KEY_SLOT_INFO)
    {
        return HandleSlotInfo(ctx.client_id, request);
    }

    // PKCS#11-specific operations — stubs for future implementation.
    if ((action == km_ops::KEY_WRAP) || (action == km_ops::KEY_UNWRAP) || (action == km_ops::KEY_DERIVE))
    {
        score::mw::log::LogError() << LOG_PREFIX << "Execute: operation not yet implemented (0x"
                                   << score::mw::log::LogHex16{action} << ")";
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
    }

    score::mw::log::LogError() << LOG_PREFIX << "Execute: unsupported action 0x" << score::mw::log::LogHex16{action};
    return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
}

// ---------------------------------------------------------------------------
// HandleGenerate
//
// Parameter layout:
//   client_id        – authenticated client (from InitializationParams)
//   context_node_id  – parent node for new key node
//   request[0]       = algorithm  (string_view)
//   request[1]       = permissions (uint32_t, optional)
//   request[2]       = public_key_permissions (uint32_t, optional, asymmetric only)
// ---------------------------------------------------------------------------

Expected<common::ResponseParameters, score::crypto::daemon::common::DaemonErrorCode>
KeyManagementExecutor::HandleGenerate(const KeyMgmtExecutionContext& ctx, common::RequestParameters& request)
{
    auto gen_req = km_parse::BuildGenerationRequest(request);
    if (!gen_req.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleGenerate: invalid request parameters";
        return score::crypto::make_unexpected(gen_req.error());
    }

    // Provider-specific: generate the key. The returned IKeyHandler owns the material.
    auto gen_result = m_factory->GenerateKey(gen_req.value());
    if (!gen_result.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleGenerate: GenerateKey failed";
        return score::crypto::make_unexpected(
            score::crypto::daemon::common::DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    // Orchestration: transfer handler ownership to the DataManager.
    // On failure the IKeyHandler destructor cleans up key material automatically.
    auto node_id_result = m_service->RegisterKeyMaterial({ctx.client_id, ctx.context_node_id, ctx.provider_id},
                                                         std::move(gen_result.value()));
    if (!node_id_result.has_value())
    {
        return score::crypto::make_unexpected(
            score::crypto::daemon::common::DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    common::ResponseParameters output;
    output.push_back(static_cast<std::uint64_t>(node_id_result.value().node_id));
    // Return the numeric provider ID assigned by ProviderManager
    output.push_back(static_cast<std::uint16_t>(ctx.provider_id));
    return output;
}

// ---------------------------------------------------------------------------
// HandleLoad
//
// Parameter layout:
//   client_id        – authenticated client (from InitializationParams)
//   context_node_id  – parent context node
//   request[0]       = slot_node_id (uint64_t)
// ---------------------------------------------------------------------------

Expected<common::ResponseParameters, score::crypto::daemon::common::DaemonErrorCode> KeyManagementExecutor::HandleLoad(
    const KeyMgmtExecutionContext& ctx,
    common::RequestParameters& request)
{
    auto slot_nid_res = km_parse::ExtractUint64(request, 0U);
    if (!slot_nid_res.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleLoad: invalid slot node id";
        return score::crypto::make_unexpected(slot_nid_res.error());
    }
    const auto slot_nid = slot_nid_res.value();

    // Orchestration: resolve slot to config.
    auto slot_res = m_service->ResolveSlotForOperation(ctx.client_id, slot_nid);
    if (!slot_res.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleLoad: slot resolution failed";
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }
    const auto& resolution = slot_res.value();

    // Orchestration: load or reuse an existing key from the registry.
    auto node_id_result = m_service->LoadOrShare(
        {ctx.client_id, ctx.context_node_id, ctx.provider_id, resolution.handle}, *m_slot_handler, *resolution.config);
    if (!node_id_result.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleLoad: LoadOrShare failed";
        return score::crypto::make_unexpected(
            score::crypto::daemon::common::DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    common::ResponseParameters output;
    output.push_back(static_cast<std::uint64_t>(node_id_result.value().node_id));
    // Return the numeric provider ID assigned by ProviderManager
    output.push_back(static_cast<std::uint16_t>(ctx.provider_id));
    return output;
}

// ---------------------------------------------------------------------------
// HandleImport
//
// Parameter layout:
//   client_id        – authenticated client (from InitializationParams)
//   context_node_id  – parent context node for the new key node
//   request[0]       = algorithm   (string_view)
//   request[1]       = permissions (uint32_t, optional)
//   request[2]       = format      (uint32_t FormatType, optional)
//   request[3]       = key_data    (span<const uint8_t>)
// ---------------------------------------------------------------------------

Expected<common::ResponseParameters, score::crypto::daemon::common::DaemonErrorCode>
KeyManagementExecutor::HandleImport(const KeyMgmtExecutionContext& ctx, common::RequestParameters& request)
{
    auto import_req = km_parse::BuildImportRequest(request);
    if (!import_req.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleImport: invalid request parameters";
        return score::crypto::make_unexpected(import_req.error());
    }

    // Provider-specific: import and validate the key. The returned IKeyHandler
    // owns the material; key_data is copied before ImportKey() returns.
    auto import_result = m_factory->ImportKey(import_req.value());
    if (!import_result.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleImport: ImportKey failed";
        return score::crypto::make_unexpected(import_result.error());
    }

    // Orchestration: transfer handler ownership to the DataManager.
    // On failure the IKeyHandler destructor cleans up key material automatically.
    auto node_id_result = m_service->RegisterKeyMaterial({ctx.client_id, ctx.context_node_id, ctx.provider_id},
                                                         std::move(import_result.value()));
    if (!node_id_result.has_value())
    {
        return score::crypto::make_unexpected(
            score::crypto::daemon::common::DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    common::ResponseParameters output;
    output.push_back(static_cast<std::uint64_t>(node_id_result.value().node_id));
    // Return the numeric provider ID assigned by ProviderManager
    output.push_back(static_cast<std::uint16_t>(ctx.provider_id));
    return output;
}

// ---------------------------------------------------------------------------
// HandleExport
//
// Parameter layout:
//   client_id   – authenticated client (from InitializationParams)
//   request[0]  = key_node_id (uint64_t)
//   request[1]  = format      (uint32_t FormatType, optional)
// Response:
//   output[0]   = exported key bytes (OwnedBuffer)
// ---------------------------------------------------------------------------

Expected<common::ResponseParameters, score::crypto::daemon::common::DaemonErrorCode>
KeyManagementExecutor::HandleExport(const KeyMgmtExecutionContext& ctx, common::RequestParameters& request)
{
    auto key_nid_res = km_parse::ExtractUint64(request, 0U);
    if (!key_nid_res.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleExport: invalid key node id";
        return score::crypto::make_unexpected(key_nid_res.error());
    }
    auto format_res = km_parse::ExtractFormatOrDefault(request, 1U);
    if (!format_res.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleExport: invalid format parameter";
        return score::crypto::make_unexpected(format_res.error());
    }
    const auto format = format_res.value();

    // Resolve the live key handler so the factory can read its provider handle.
    auto handler_res = m_service->ResolveKeyForOperation(ctx.client_id, key_nid_res.value());
    if (!handler_res.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleExport: key resolution failed";
        return score::crypto::make_unexpected(handler_res.error());
    }

    const auto& handle = handler_res.value()->GetHandle();

    // A handle's opaque_id is only meaningful to the provider that issued it;
    // letting another provider's factory reinterpret it as its own pointer
    // would dereference a foreign address and crash the daemon (SIGSEGV).
    if (handle.provider_id != ctx.provider_id)
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleExport: key provider " << handle.provider_id
                                   << " does not match context provider " << ctx.provider_id;
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    auto export_res = m_factory->ExportKey(handle, format);
    if (!export_res.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleExport: ExportKey failed";
        return score::crypto::make_unexpected(export_res.error());
    }

    common::ResponseParameters output;
    // Move the bytes out of SecureKeyBytes; the moved-from vector empties, so
    // its zeroizing destructor has nothing left to scrub.
    output.push_back(common::OwnedBuffer{std::move(export_res.value().bytes)});
    return output;
}

// ---------------------------------------------------------------------------
// HandleGetExportSize
//
// Parameter layout:
//   client_id   – authenticated client (from InitializationParams)
//   request[0]  = key_node_id (uint64_t)
//   request[1]  = format      (uint32_t FormatType, optional)
// Response:
//   output[0]   = exported byte length (uint64_t)
// ---------------------------------------------------------------------------

Expected<common::ResponseParameters, score::crypto::daemon::common::DaemonErrorCode>
KeyManagementExecutor::HandleGetExportSize(const KeyMgmtExecutionContext& ctx, common::RequestParameters& request)
{
    auto key_nid_res = km_parse::ExtractUint64(request, 0U);
    if (!key_nid_res.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleGetExportSize: invalid key node id";
        return score::crypto::make_unexpected(key_nid_res.error());
    }
    auto format_res = km_parse::ExtractFormatOrDefault(request, 1U);
    if (!format_res.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleGetExportSize: invalid format parameter";
        return score::crypto::make_unexpected(format_res.error());
    }
    const auto format = format_res.value();

    auto handler_res = m_service->ResolveKeyForOperation(ctx.client_id, key_nid_res.value());
    if (!handler_res.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleGetExportSize: key resolution failed";
        return score::crypto::make_unexpected(handler_res.error());
    }

    const auto& handle = handler_res.value()->GetHandle();

    // Reject a key owned by a different provider before the factory reinterprets
    // its opaque_id as a native pointer (mismatched provider => SIGSEGV).
    if (handle.provider_id != ctx.provider_id)
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleGetExportSize: key provider " << handle.provider_id
                                   << " does not match context provider " << ctx.provider_id;
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    auto size_res = m_factory->GetExportKeySize(handle, format);
    if (!size_res.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleGetExportSize: GetExportKeySize failed";
        return score::crypto::make_unexpected(size_res.error());
    }

    common::ResponseParameters output;
    output.push_back(static_cast<std::uint64_t>(size_res.value()));
    return output;
}

// ---------------------------------------------------------------------------
// HandleRelease
//
// Parameter layout:
//   client_id   – authenticated client (from InitializationParams)
//   request[0]  = key_node_id (uint64_t)
// ---------------------------------------------------------------------------

Expected<common::ResponseParameters, score::crypto::daemon::common::DaemonErrorCode>
KeyManagementExecutor::HandleRelease(std::uint64_t client_id, common::RequestParameters& request)
{
    auto key_nid_res = km_parse::ExtractUint64(request, 0U);
    if (!key_nid_res.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleRelease: invalid key node id";
        return score::crypto::make_unexpected(key_nid_res.error());
    }

    auto release_result = m_service->ReleaseKeyMaterial(client_id, key_nid_res.value());
    if (!release_result.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleRelease: release failed";
        return score::crypto::make_unexpected(
            score::crypto::daemon::common::DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    common::ResponseParameters output;
    output.push_back(static_cast<std::uint64_t>(0U));  // success
    return output;
}

// ---------------------------------------------------------------------------
// HandleSlotInfo
//
// Parameter layout:
//   client_id   – authenticated client (from InitializationParams)
//   request[0]  = slot_node_id (uint64_t)
// ---------------------------------------------------------------------------

Expected<common::ResponseParameters, score::crypto::daemon::common::DaemonErrorCode>
KeyManagementExecutor::HandleSlotInfo(std::uint64_t client_id, common::RequestParameters& request)
{
    auto slot_nid_res = km_parse::ExtractUint64(request, 0U);
    if (!slot_nid_res.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleSlotInfo: invalid slot node id";
        return score::crypto::make_unexpected(slot_nid_res.error());
    }

    auto slot_res = m_service->ResolveSlotForOperation(client_id, slot_nid_res.value());
    if (!slot_res.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleSlotInfo: slot resolution failed";
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    // Provider-specific: query slot metadata.
    auto info_result = m_slot_handler->GetSlotInfo(*slot_res.value().config);
    if (!info_result.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleSlotInfo: GetSlotInfo failed";
        return score::crypto::make_unexpected(
            score::crypto::daemon::common::DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    const auto& info = info_result.value();
    common::ResponseParameters output;
    output.push_back(static_cast<std::uint64_t>(info.state));
    output.push_back(static_cast<std::uint64_t>(info.state != score::crypto::KeySlotState::kEmpty ? 1U : 0U));
    output.push_back(static_cast<std::uint64_t>(info.permitted_operations));
    return output;
}

}  // namespace score::crypto::daemon::provider::crypto_executor

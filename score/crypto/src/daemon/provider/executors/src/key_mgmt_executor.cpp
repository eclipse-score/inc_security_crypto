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

#include "score/crypto/src/daemon/key_management/core/key_entry.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_management_operations.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_types.hpp"
#include "score/crypto/src/daemon/provider/executors/key_mgmt_request_parser.hpp"

#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/mw/log/logging.h"

#include <algorithm>
#include <string_view>
#include <variant>

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
        return HandleSlotInfo(ctx, request);
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

Expected<common::ProviderId, score::crypto::daemon::common::DaemonErrorCode> KeyManagementExecutor::OwnerOf(
    const key_management::SlotResolution& resolution) const
{
    // Slot handlers are provider-specific, so a slot is only ever accessed
    // through its owner. A slot whose configured provider was not registered
    // at startup has no owner and is refused instead of being guessed at.
    auto owner = m_service->GetSlotRegistry()->GetPrimaryProviderId(resolution.handle);
    if (!owner.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "slot '" << resolution.config->slot_name
                                   << "' has no available provider";
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kResourceNotFound);
    }
    return owner.value();
}

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

    // The loaded key is registered with this context's provider, so a slot owned
    // by another provider is refused, as in BindKeyToContext; m_slot_handler
    // could not read it anyway.
    const auto slot_provider = OwnerOf(resolution);
    if (!slot_provider.has_value())
    {
        return score::crypto::make_unexpected(slot_provider.error());
    }
    if (slot_provider.value() != ctx.provider_id)
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleLoad: cross-provider load not supported (slot provider="
                                   << slot_provider.value() << ", context provider=" << ctx.provider_id << ")";
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
    }

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

    // Resolve the owning KeyEntry so the factory can read its provider handle.
    // Holding the KeyEntry (not just the handler) for the whole operation keeps
    // the key material alive: a concurrent release from another context cannot
    // run ~KeyEntry -> IKeyHandler::Release() and free it mid-export.
    auto entry_res = m_service->ResolveKeyForOperation(ctx.client_id, key_nid_res.value());
    if (!entry_res.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleExport: key resolution failed";
        return score::crypto::make_unexpected(entry_res.error());
    }

    const auto& handle = entry_res.value()->GetHandle();

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

    auto& exported = export_res.value().bytes;

    // Data-plane path: when the client supplied an output shared-memory buffer
    // (resolved to a writable span by the ShmRequestHandler), write the exported
    // bytes directly into it and return only the written length. This keeps the
    // key material out of the in-band control-plane response.
    if (request.size() > 2U)
    {
        if (auto* out_span = std::get_if<score::cpp::span<uint8_t>>(&request[2U]))
        {
            if (out_span->size() < exported.size())
            {
                score::mw::log::LogError() << LOG_PREFIX << "HandleExport: output buffer too small";
                return score::crypto::make_unexpected(
                    score::crypto::daemon::common::DaemonErrorCode::kInsufficientBufferSize);
            }
            std::copy(exported.begin(), exported.end(), out_span->begin());

            common::ResponseParameters output;
            output.push_back(static_cast<std::uint64_t>(exported.size()));
            return output;
        }
    }

    // Control-plane fallback: return the exported bytes in-band.
    common::ResponseParameters output;
    // Move the bytes out of SecureKeyBytes; the moved-from vector empties, so
    // its zeroizing destructor has nothing left to scrub.
    output.push_back(common::OwnedBuffer{std::move(exported)});
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

    // Hold the owning KeyEntry for the whole operation so a concurrent release
    // from another context cannot free the key material before GetExportKeySize.
    auto entry_res = m_service->ResolveKeyForOperation(ctx.client_id, key_nid_res.value());
    if (!entry_res.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleGetExportSize: key resolution failed";
        return score::crypto::make_unexpected(entry_res.error());
    }

    const auto& handle = entry_res.value()->GetHandle();

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
//
// Response layout:
//   [0] = state (uint64_t, KeySlotState)
//   [1] = occupied flag (uint64_t, 0/1)
//   [2] = permitted operations (uint64_t, KeyOperationPermission bits)
//   [3] = slot algorithm (string, empty when unconstrained)
//   [4] = primary provider id (uint16_t)
//   [5..] = compatible provider ids (uint16_t each)
// ---------------------------------------------------------------------------

Expected<common::ResponseParameters, score::crypto::daemon::common::DaemonErrorCode>
KeyManagementExecutor::HandleSlotInfo(const KeyMgmtExecutionContext& ctx, common::RequestParameters& request)
{
    auto slot_nid_res = km_parse::ExtractUint64(request, 0U);
    if (!slot_nid_res.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleSlotInfo: invalid slot node id";
        return score::crypto::make_unexpected(slot_nid_res.error());
    }

    auto slot_res = m_service->ResolveSlotForOperation(ctx.client_id, slot_nid_res.value());
    if (!slot_res.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleSlotInfo: slot resolution failed";
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    // Only the provider that owns the slot can read it: each provider's slot
    // handler looks for its own entries in the deployment file and reports any
    // other provider's slot as empty. The context may be served by another
    // provider, so a foreign slot is queried through its primary provider.
    const auto& resolution = slot_res.value();
    const auto slot_provider = OwnerOf(resolution);
    if (!slot_provider.has_value())
    {
        return score::crypto::make_unexpected(slot_provider.error());
    }
    auto slot_handler = m_slot_handler;
    if (slot_provider.value() != ctx.provider_id)
    {
        auto owner_handler = m_service->GetSlotHandler(slot_provider.value(), *resolution.config);
        if (!owner_handler.has_value())
        {
            score::mw::log::LogError() << LOG_PREFIX << "HandleSlotInfo: no slot handler for provider "
                                       << slot_provider.value();
            return score::crypto::make_unexpected(owner_handler.error());
        }
        slot_handler = std::move(owner_handler).value();
    }

    auto info_result = slot_handler->GetSlotInfo(*resolution.config);
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
    output.push_back(common::OwnedString{std::string_view{info.algorithm}});
    output.push_back(info.primary_provider);
    for (std::size_t i = 0U; i < info.compatible_provider_count; ++i)
    {
        output.push_back(info.compatible_providers.at(i));
    }
    return output;
}

}  // namespace score::crypto::daemon::provider::crypto_executor

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
#include <utility>

namespace score::crypto::daemon::provider::crypto_executor
{
namespace
{
constexpr std::string_view LOG_PREFIX = "[KEY_MGMT_EXEC] ";

namespace km_ops = key_management::operations;
namespace km_parse = key_mgmt_request_parser;
namespace km = key_management;
using Error = common::DaemonErrorCode;
using Permission = score::crypto::KeyOperationPermission;
using InputBytes = score::cpp::span<const std::uint8_t>;

// ---------------------------------------------------------------------------
// Request validation helpers
// ---------------------------------------------------------------------------

// Returns the requested parameter when its packed type matches T.
template <typename T>
[[nodiscard]] const T* Parameter(const common::RequestParameters& request, std::size_t index)
{
    return index < request.size() ? std::get_if<T>(&request[index]) : nullptr;
}

// Validates a non-empty, non-truncated algorithm identifier.
[[nodiscard]] bool ValidAlgorithm(std::string_view value)
{
    return (!value.empty()) && (value.size() <= score::crypto::AlgorithmId::max_capacity) &&
           (value.find('\0') == std::string_view::npos);
}

// Validates that no unsupported key-operation-permission bits are set.
[[nodiscard]] bool ValidPermissions(std::uint64_t value)
{
    return value <= static_cast<std::uint64_t>(Permission::kAll);
}
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
    if (action == km_ops::KEY_GET_ENCAPSULATION_SIZE)
    {
        return HandleGetEncapsulationCiphertextSize(ctx, request);
    }
    if (action == km_ops::KEY_ENCAPSULATE)
    {
        return HandleEncapsulateKey(ctx, request);
    }
    if (action == km_ops::KEY_DECAPSULATE)
    {
        return HandleDecapsulateKey(ctx, request);
    }
    if (action == km_ops::KEY_IMPORT)
    {
        return HandleImport(ctx, request);
    }
    if (action == km_ops::KEY_GET_EXPORT_SIZE)
    {
        return HandleGetExportKeySize(ctx, request);
    }
    if (action == km_ops::KEY_EXPORT)
    {
        return HandleExportKey(ctx, request);
    }
    if (action == km_ops::KEY_GENERATE)
    {
        return HandleGenerate(ctx, request);
    }
    if (action == km_ops::KEY_LOAD)
    {
        return HandleLoad(ctx, request);
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
    if ((action == km_ops::KEY_WRAP) || (action == km_ops::KEY_UNWRAP))
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

// ---------------------------------------------------------------------------
// RegisterOutput
//
// Registers provider-created ephemeral key material in the caller's context.
// ---------------------------------------------------------------------------

Expected<data_manager::DataNodeId, Error> KeyManagementExecutor::RegisterOutput(const KeyMgmtExecutionContext& ctx,
                                                                                km::IKeyHandler::Sptr key)
{
    if ((!key) || (key->GetProviderId() != ctx.provider_id) ||
        (key->GetHandle().provider_id != ctx.provider_id))
    {
        return make_unexpected(Error::kOperationFailed);
    }
    auto registered =
        m_service->RegisterKeyMaterial({ctx.client_id, ctx.context_node_id, ctx.provider_id}, std::move(key));
    if (!registered.has_value())
    {
        return make_unexpected(registered.error());
    }
    return registered.value().node_id;
}

// ---------------------------------------------------------------------------
// HandleGetEncapsulationCiphertextSize
//
// Parameter layout:
//   request[0] = algorithm (string_view)
//   request[1] = peer public-key node id (uint64_t)
// ---------------------------------------------------------------------------

Expected<common::ResponseParameters, Error> KeyManagementExecutor::HandleGetEncapsulationCiphertextSize(
    const KeyMgmtExecutionContext& ctx,
    const common::RequestParameters& request)
{
    if (request.size() != 2U)
    {
        return make_unexpected(Error::kInvalidArgument);
    }
    const auto* algorithm = Parameter<std::string_view>(request, 0U);
    const auto* key_id = Parameter<std::uint64_t>(request, 1U);
    if ((!algorithm) || (!ValidAlgorithm(*algorithm)) || (!key_id) || (*key_id == 0U))
    {
        return make_unexpected(Error::kInvalidArgument);
    }
    auto lease = m_service->AcquireKeyForOperation(ctx.client_id, *key_id, ctx.provider_id, Permission::kAgree);
    if (!lease.has_value())
    {
        return make_unexpected(lease.error());
    }
    const auto& key = lease.value().Handler();
    if (key.GetHandle().algorithm != *algorithm)
    {
        return make_unexpected(Error::kInvalidArgument);
    }

    if (key.GetHandle().material_kind != km::KeyMaterialKind::kPublicKey)
    {
        return make_unexpected(Error::kInvalidArgument);
    }
    const km::KeyEncapsulationRequest params{key, std::string{*algorithm}};
    auto size = m_factory->GetEncapsulationCiphertextSize(params);
    if (!size.has_value())
    {
        return make_unexpected(size.error());
    }
    if (size.value() == 0U)
    {
        return make_unexpected(Error::kOperationFailed);
    }
    return common::ResponseParameters{static_cast<std::uint64_t>(size.value())};
}

// ---------------------------------------------------------------------------
// HandleEncapsulateKey
//
// Parameter layout:
//   request[0] = algorithm (string_view)
//   request[1] = peer public-key node id (uint64_t)
//   request[2] = ciphertext capacity (uint64_t)
// ---------------------------------------------------------------------------

Expected<common::ResponseParameters, Error> KeyManagementExecutor::HandleEncapsulateKey(
    const KeyMgmtExecutionContext& ctx,
    const common::RequestParameters& request)
{
    if (request.size() != 3U)
    {
        return make_unexpected(Error::kInvalidArgument);
    }
    const auto* algorithm = Parameter<std::string_view>(request, 0U);
    const auto* key_id = Parameter<std::uint64_t>(request, 1U);
    const auto* capacity = Parameter<std::uint64_t>(request, 2U);
    if ((!algorithm) || (!ValidAlgorithm(*algorithm)) || (!key_id) || (*key_id == 0U) || (!capacity))
    {
        return make_unexpected(Error::kInvalidArgument);
    }
    auto lease = m_service->AcquireKeyForOperation(ctx.client_id, *key_id, ctx.provider_id, Permission::kAgree);
    if (!lease.has_value())
    {
        return make_unexpected(lease.error());
    }
    const auto& key = lease.value().Handler();
    if ((key.GetHandle().algorithm != *algorithm) ||
        (key.GetHandle().material_kind != km::KeyMaterialKind::kPublicKey))
    {
        return make_unexpected(Error::kInvalidArgument);
    }
    const km::KeyEncapsulationRequest params{key, std::string{*algorithm}};
    auto size = m_factory->GetEncapsulationCiphertextSize(params);
    if (!size.has_value())
    {
        return make_unexpected(size.error());
    }
    if (size.value() == 0U)
    {
        return make_unexpected(Error::kOperationFailed);
    }
    if (*capacity < size.value())
    {
        return make_unexpected(Error::kInsufficientBufferSize);
    }
    auto result = m_factory->EncapsulateKey(params);
    if (!result.has_value())
    {
        return make_unexpected(result.error());
    }
    if (result.value().ciphertext.size() != size.value())
    {
        return make_unexpected(Error::kOperationFailed);
    }
    auto secret = std::move(result.value().shared_secret);
    if ((!secret) || (secret->GetHandle().material_kind != km::KeyMaterialKind::kSharedSecret) ||
        (secret->GetHandle().permissions != Permission::kDerive) || (secret->GetHandle().is_asymmetric) ||
        (secret->GetHandle().key_size == 0U))
    {
        return make_unexpected(Error::kOperationFailed);
    }
    common::ResponseParameters output;
    output.reserve(3U);
    output.emplace_back(std::move(result.value().ciphertext));
    auto id = RegisterOutput(ctx, std::move(secret));
    if (!id.has_value())
    {
        return make_unexpected(id.error());
    }
    output.emplace_back(static_cast<std::uint64_t>(id.value()));
    output.emplace_back(static_cast<std::uint16_t>(ctx.provider_id));
    return output;
}

// ---------------------------------------------------------------------------
// HandleDecapsulateKey
//
// Parameter layout:
//   request[0] = algorithm (string_view)
//   request[1] = private-key node id (uint64_t)
//   request[2] = ciphertext (InputBytes)
// ---------------------------------------------------------------------------

Expected<common::ResponseParameters, Error> KeyManagementExecutor::HandleDecapsulateKey(
    const KeyMgmtExecutionContext& ctx,
    const common::RequestParameters& request)
{
    if (request.size() != 3U)
    {
        return make_unexpected(Error::kInvalidArgument);
    }
    const auto* algorithm = Parameter<std::string_view>(request, 0U);
    const auto* key_id = Parameter<std::uint64_t>(request, 1U);
    const auto* ciphertext = Parameter<InputBytes>(request, 2U);
    if ((!algorithm) || (!ValidAlgorithm(*algorithm)) || (!key_id) || (*key_id == 0U) || (!ciphertext) ||
        (ciphertext->empty()) || (ciphertext->data() == nullptr))
    {
        return make_unexpected(Error::kInvalidArgument);
    }
    auto lease = m_service->AcquireKeyForOperation(ctx.client_id, *key_id, ctx.provider_id, Permission::kAgree);
    if (!lease.has_value())
    {
        return make_unexpected(lease.error());
    }
    const auto& key = lease.value().Handler();
    if ((key.GetHandle().algorithm != *algorithm) ||
        (key.GetHandle().material_kind != km::KeyMaterialKind::kPrivateKey))
    {
        return make_unexpected(Error::kInvalidArgument);
    }
    auto result = m_factory->DecapsulateKey({key, std::string{*algorithm}, *ciphertext});
    if (!result.has_value())
    {
        return make_unexpected(result.error());
    }
    auto secret = std::move(result.value());
    if ((!secret) || (secret->GetHandle().material_kind != km::KeyMaterialKind::kSharedSecret) ||
        (secret->GetHandle().permissions != Permission::kDerive) || (secret->GetHandle().is_asymmetric) ||
        (secret->GetHandle().key_size == 0U))
    {
        return make_unexpected(Error::kOperationFailed);
    }
    auto id = RegisterOutput(ctx, std::move(secret));
    if (!id.has_value())
    {
        return make_unexpected(id.error());
    }
    return common::ResponseParameters{static_cast<std::uint64_t>(id.value()),
                                      static_cast<std::uint16_t>(ctx.provider_id)};
}

// ---------------------------------------------------------------------------
// HandleImport
//
// Parameter layout:
//   request[0] = algorithm (string_view)
//   request[1] = key material (InputBytes)
//   request[2] = format (uint8_t)
//   request[3] = permissions (uint32_t)
// ---------------------------------------------------------------------------

Expected<common::ResponseParameters, Error> KeyManagementExecutor::HandleImport(
    const KeyMgmtExecutionContext& ctx,
    const common::RequestParameters& request)
{
    if (request.size() != 4U)
    {
        return make_unexpected(Error::kInvalidArgument);
    }
    const auto* algorithm = Parameter<std::string_view>(request, 0U);
    const auto* data = Parameter<InputBytes>(request, 1U);
    const auto* format = Parameter<std::uint8_t>(request, 2U);
    const auto* permissions = Parameter<std::uint32_t>(request, 3U);
    if ((!algorithm) || (!ValidAlgorithm(*algorithm)) || (!data) || (data->empty()) || (!data->data()) ||
        (!format) || (*format > static_cast<std::uint8_t>(score::crypto::FormatType::kRaw)) || (!permissions) ||
        (!ValidPermissions(*permissions)))
    {
        return make_unexpected(Error::kInvalidArgument);
    }
    km::KeyImportRequest params;
    params.algorithm = std::string{*algorithm};
    params.key_data = data->data();
    params.key_data_size = data->size();
    params.format = static_cast<score::crypto::FormatType>(*format);
    params.permissions = static_cast<Permission>(*permissions);
    common::ResponseParameters output;
    output.reserve(2U);
    auto result = m_factory->ImportKey(params);
    if (!result.has_value())
    {
        return make_unexpected(result.error());
    }
    if (!result.value())
    {
        return make_unexpected(Error::kOperationFailed);
    }

    const auto& handle = result.value()->GetHandle();
    const auto actual_permissions =
        handle.material_kind == km::KeyMaterialKind::kPublicKey
            ? handle.public_key_permissions.value_or(Permission::kAll)
            : handle.permissions;

    if (handle.algorithm != params.algorithm || actual_permissions != params.permissions || handle.key_size == 0U)
    {
        return make_unexpected(Error::kOperationFailed);
    }

    auto id = RegisterOutput(ctx, std::move(result.value()));
    if (!id.has_value())
    {
        return make_unexpected(id.error());
    }
    output.emplace_back(static_cast<std::uint64_t>(id.value()));
    output.emplace_back(static_cast<std::uint16_t>(ctx.provider_id));
    return output;
}

// ---------------------------------------------------------------------------
// HandleGetExportKeySize
//
// Parameter layout:
//   request[0] = key node id (uint64_t)
//   request[1] = format (uint8_t)
// ---------------------------------------------------------------------------

Expected<common::ResponseParameters, Error> KeyManagementExecutor::HandleGetExportKeySize(
    const KeyMgmtExecutionContext& ctx,
    const common::RequestParameters& request)
{
    if (request.size() != 2U)
    {
        return make_unexpected(Error::kInvalidArgument);
    }
    const auto* key_id = Parameter<std::uint64_t>(request, 0U);
    const auto* format = Parameter<std::uint8_t>(request, 1U);
    if ((!key_id) || (*key_id == 0U) || (!format) ||
        (*format > static_cast<std::uint8_t>(score::crypto::FormatType::kRaw)))
    {
        return make_unexpected(Error::kInvalidArgument);
    }
    auto lease = m_service->AcquireKeyForOperation(ctx.client_id, *key_id, ctx.provider_id, Permission::kExport);
    if (!lease.has_value())
    {
        return make_unexpected(lease.error());
    }
    const auto encoding = static_cast<score::crypto::FormatType>(*format);
    // Raw material is exported by the live key handler. Providers retain
    // ownership of DER/PEM encoding for their asymmetric-key formats.
    auto exported = encoding == score::crypto::FormatType::kRaw
                        ? lease.value().Handler().Export()
                        : m_factory->ExportKey(lease.value().Handler().GetHandle(), encoding);
    if (!exported.has_value())
    {
        return make_unexpected(exported.error());
    }
    return common::ResponseParameters{static_cast<std::uint64_t>(exported.value().bytes.size())};
}

// ---------------------------------------------------------------------------
// HandleExportKey
//
// Parameter layout:
//   request[0] = key node id (uint64_t)
//   request[1] = format (uint8_t)
// ---------------------------------------------------------------------------

Expected<common::ResponseParameters, Error> KeyManagementExecutor::HandleExportKey(
    const KeyMgmtExecutionContext& ctx,
    const common::RequestParameters& request)
{
    if (request.size() != 2U)
    {
        return make_unexpected(Error::kInvalidArgument);
    }
    const auto* key_id = Parameter<std::uint64_t>(request, 0U);
    const auto* format = Parameter<std::uint8_t>(request, 1U);
    if ((!key_id) || (*key_id == 0U) || (!format) ||
        (*format > static_cast<std::uint8_t>(score::crypto::FormatType::kRaw)))
    {
        return make_unexpected(Error::kInvalidArgument);
    }
    auto lease = m_service->AcquireKeyForOperation(ctx.client_id, *key_id, ctx.provider_id, Permission::kExport);
    if (!lease.has_value())
    {
        return make_unexpected(lease.error());
    }
    const auto encoding = static_cast<score::crypto::FormatType>(*format);
    // Raw material is exported by the live key handler. Providers retain
    // ownership of DER/PEM encoding for their asymmetric-key formats.
    auto exported = encoding == score::crypto::FormatType::kRaw
                        ? lease.value().Handler().Export()
                        : m_factory->ExportKey(lease.value().Handler().GetHandle(), encoding);
    if (!exported.has_value())
    {
        return make_unexpected(exported.error());
    }
    return common::ResponseParameters{common::OwnedBuffer{std::move(exported.value().bytes)}};
}

}  // namespace score::crypto::daemon::provider::crypto_executor

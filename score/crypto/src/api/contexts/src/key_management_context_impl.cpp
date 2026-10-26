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

#include "score/crypto/src/api/contexts/src/key_management_context_impl.hpp"

#include "score/crypto/src/api/common/crypto_resource_guard.hpp"
#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/common/src/crypto_resource_guard_factory.hpp"
#include "score/crypto/src/api/common/src/i_release_callback.hpp"
#include "score/crypto/src/api/config/key_operation_params.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/api/types/key.hpp"

#include "score/crypto/src/api/control_plane/i_connection.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/key_management/interfaces/key_management_operations.hpp"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"

#include "score/result/result.h"
#include "score/span.hpp"

#include "score/mw/log/logging.h"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>

#include <memory>
#include <optional>
#include <utility>
#include <variant>

namespace score
{

namespace crypto
{

namespace proto = ::score::crypto::daemon::control_plane::protocol;
namespace actors = ::score::crypto::daemon::common::actors;
namespace keymgmt_ops = ::score::crypto::daemon::key_management::operations;

// ---------------------------------------------------------------------------
// IReleaseCallback implementation — sends CTX_CLOSE on last reference drop
// ---------------------------------------------------------------------------
class KeyManagementContextImpl::ContextReleaseCallbackImpl final : public IReleaseCallback
{
  public:
    ContextReleaseCallbackImpl(std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
                               proto::DataNodeId context_id)
        : m_connection(std::move(connection)), m_context_id(context_id)
    {
    }

    // No copy, no move. Just handled via shared_ptr
    ContextReleaseCallbackImpl(const ContextReleaseCallbackImpl&) = delete;
    ContextReleaseCallbackImpl& operator=(const ContextReleaseCallbackImpl&) = delete;
    ContextReleaseCallbackImpl(ContextReleaseCallbackImpl&&) = delete;
    ContextReleaseCallbackImpl& operator=(ContextReleaseCallbackImpl&&) = delete;

    ~ContextReleaseCallbackImpl() override
    {
        if (!m_connection)
        {
            score::mw::log::LogError()
                << "[API][KeyMgmtContextImpl] ERROR: Connection is not initialized during CTX_CLOSE";
            return;
        }

        auto context_close_res = proto::ControlRequestBuilder()
                                     .forDataNodeId(m_context_id)
                                     .operation(score::crypto::daemon::mediator::operations::CloseContext())
                                     .build();

        if (!context_close_res.has_value())
        {
            score::mw::log::LogError() << "[API][KeyMgmtContextImpl] ERROR: Failed to build CTX_CLOSE request";
            return;
        }

        auto response_res = m_connection->SendRequest(context_close_res.value());

        auto validator = proto::ControlResponseValidator::FromResult(response_res);
        validator.expectOperation(score::crypto::daemon::mediator::operations::CloseContext()).expectSuccess();

        if (!validator.isValid())
        {
            score::mw::log::LogError() << "[API][KeyMgmtContextImpl] ERROR: CTX_CLOSE response validation failed: "
                                       << validator.getError();
            return;
        }
    }

    score::Result<std::monostate> ReleaseResource(const CryptoResourceId& /*id*/) noexcept override
    {
        return std::monostate{};
    }

  private:
    std::shared_ptr<score::crypto::api::control_plane::IConnection> m_connection;
    proto::DataNodeId m_context_id;
};

// ---------------------------------------------------------------------------
// IReleaseCallback implementation — sends KEY_RELEASE to daemon
// ---------------------------------------------------------------------------
class KeyManagementContextImpl::ReleaseCallbackImpl final : public IReleaseCallback
{
  public:
    ReleaseCallbackImpl(std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
                        proto::DataNodeId context_id,
                        std::shared_ptr<IReleaseCallback> context_release_callback)
        : m_connection(std::move(connection)),
          m_context_id(context_id),
          m_context_release_callback(std::move(context_release_callback))
    {
    }

    score::Result<std::monostate> ReleaseResource(const CryptoResourceId& id) noexcept override
    {
        auto control_req_result = proto::ControlRequestBuilder()
                                      .forDataNodeId(m_context_id)
                                      .operation({actors::OP_ACTOR_KEY_MANAGEMENT, keymgmt_ops::KEY_RELEASE})
                                      .with_in_val_uint64(id.id)
                                      .build();
        if (!control_req_result.has_value())
        {
            score::mw::log::LogError() << "[API][KeyMgmtRelease] ERROR: Failed to build KEY_RELEASE request";
            return score::Result<std::monostate>{
                score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build KEY_RELEASE request")};
        }

        auto control_response_res = m_connection->SendRequest(control_req_result.value());

        auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
        validator.expectOperation({actors::OP_ACTOR_KEY_MANAGEMENT, keymgmt_ops::KEY_RELEASE}).expectSuccess();

        if (!validator.isValid())
        {
            score::mw::log::LogError() << "[API][KeyMgmtRelease] ERROR:" << validator.getError();
            return score::Result<std::monostate>{
                score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "KEY_RELEASE daemon response invalid")};
        }

        return std::monostate{};
    }

  private:
    std::shared_ptr<score::crypto::api::control_plane::IConnection> m_connection;
    proto::DataNodeId m_context_id;
    std::shared_ptr<IReleaseCallback> m_context_release_callback;
};

KeyManagementContextImpl::KeyManagementContextImpl(
    std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
    uint64_t context_id)
    : m_connection(std::move(connection)),
      m_context_id(context_id),
      m_context_release_callback(std::make_shared<ContextReleaseCallbackImpl>(m_connection, m_context_id)),
      m_release_callback(std::make_shared<ReleaseCallbackImpl>(m_connection, m_context_id, m_context_release_callback))
{
}

KeyManagementContextImpl::~KeyManagementContextImpl() = default;

// ---------------------------------------------------------------------------
// Internal IPC helpers
// ---------------------------------------------------------------------------

score::Result<proto::SingleOperationResponse> KeyManagementContextImpl::ExchangeKeyOperation(
    const Expected<proto::ControlRequest, CryptoErrorCode>& request,
    std::size_t response_parameter_count)
{
    if (!request.has_value())
    {
        return score::Result<proto::SingleOperationResponse>{score::unexpect, MakeError(request.error())};
    }
    if (!m_connection)
    {
        return score::Result<proto::SingleOperationResponse>{score::unexpect,
                                                             MakeError(CryptoErrorCode::kConnectionFailed)};
    }
    auto response = m_connection->SendRequest(request.value());
    if (!response.has_value())
    {
        return score::Result<proto::SingleOperationResponse>{score::unexpect, MakeError(response.error())};
    }
    auto& operations = response.value().operation.operations;
    if (operations.size() != 1U || operations[0].operationId.operationActor != actors::OP_ACTOR_KEY_MANAGEMENT ||
        operations[0].operationId.operationAction !=
            request.value().operation.operations[0].operationId.operationAction)
    {
        return score::Result<proto::SingleOperationResponse>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Invalid key operation response")};
    }
    if (operations[0].result != proto::OPERATION_RESULT_SUCCESS)
    {
        return score::Result<proto::SingleOperationResponse>{
            score::unexpect, MakeError(static_cast<CryptoErrorCode>(operations[0].result))};
    }
    if (operations[0].parameters.size() != response_parameter_count)
    {
        return score::Result<proto::SingleOperationResponse>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Invalid key response parameter count")};
    }
    return std::move(operations[0]);
}

score::Result<CryptoResourceGuard> KeyManagementContextImpl::MakeKeyGuard(
    const daemon::common::ResponseParameters& parameters,
    std::size_t offset)
{
    if (parameters.size() < offset + 2U)
    {
        return score::Result<CryptoResourceGuard>{score::unexpect, MakeError(CryptoErrorCode::kOperationFailed)};
    }
    const auto* id = std::get_if<std::uint64_t>(&parameters[offset]);
    const auto* provider = std::get_if<std::uint16_t>(&parameters[offset + 1U]);
    if (!id || *id == 0U || !provider || *provider == daemon::common::kInvalidProviderId)
    {
        return score::Result<CryptoResourceGuard>{score::unexpect, MakeError(CryptoErrorCode::kOperationFailed)};
    }
    return CryptoResourceGuardFactory::Make(
        m_release_callback, CryptoResourceId{*id, ResourceType::kKey, ResourcePersistence::kEphemeral, *provider});
}

// ---------------------------------------------------------------------------
// Key Generation — Ephemeral
// ---------------------------------------------------------------------------

score::Result<CryptoResourceGuard> KeyManagementContextImpl::GenerateKey(const GenerateKeyParams& params)
{
    auto request_builder = proto::ControlRequestBuilder()
                               .forDataNodeId(m_context_id)
                               .operation({actors::OP_ACTOR_KEY_MANAGEMENT, keymgmt_ops::KEY_GENERATE})
                               .with_in_string(params.algorithm)
                               .with_in_val_uint32(static_cast<std::uint32_t>(params.permissions));

    // Only sent when the caller restricted the public half. Omitting the
    // parameter is what tells the daemon to leave it unrestricted, so an
    // unconditional send would silently turn the default into kAll-explicit.
    if (params.public_key_permissions.has_value())
    {
        request_builder =
            request_builder.with_in_val_uint32(static_cast<std::uint32_t>(params.public_key_permissions.value()));
    }

    auto control_req_result = request_builder.build();

    if (!control_req_result.has_value())
    {
        score::mw::log::LogError() << "[API][KeyMgmtContextImpl] ERROR: Failed to build KEY_GENERATE request";
        return score::Result<CryptoResourceGuard>{
            score::unexpect, MakeError(CryptoErrorCode::kKeyGenerationFailed, "Failed to build KEY_GENERATE request")};
    }

    auto control_response_res = m_connection->SendRequest(control_req_result.value());

    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation({actors::OP_ACTOR_KEY_MANAGEMENT, keymgmt_ops::KEY_GENERATE}).expectSuccess();

    if (!validator.isValid())
    {
        score::mw::log::LogError() << "[API][KeyMgmtContextImpl] ERROR:" << validator.getError();
        return score::Result<CryptoResourceGuard>{
            score::unexpect, MakeError(CryptoErrorCode::kKeyGenerationFailed, "KEY_GENERATE daemon response invalid")};
    }

    // Extract the daemon-assigned resource id from the response
    auto resource_id_result = validator.getParameterAt<std::uint64_t>(0, 0);
    if (!resource_id_result.has_value())
    {
        score::mw::log::LogError()
            << "[API][KeyMgmtContextImpl] ERROR: KEY_GENERATE response has invalid resource_id type";
        return score::Result<CryptoResourceGuard>{
            score::unexpect,
            MakeError(CryptoErrorCode::kKeyGenerationFailed, "KEY_GENERATE response has invalid resource_id type")};
    }

    CryptoResourceId resource_id{};
    resource_id.id = resource_id_result.value();
    resource_id.type = ResourceType::kKey;
    resource_id.persistence = ResourcePersistence::kEphemeral;

    // Extract optional provider id from response (param 0, index 1)
    auto provider_result = validator.getParameterAt<std::uint16_t>(0, 1);
    if (provider_result.has_value())
    {
        resource_id.primary_provider = provider_result.value();
    }

    return CryptoResourceGuardFactory::Make(m_release_callback, resource_id);
}

score::Result<CryptoResourceGuard> KeyManagementContextImpl::LoadKey(const CryptoResourceId& slot)
{
    if (slot.type != ResourceType::kKeySlot)
    {
        score::mw::log::LogError() << "[API][KeyMgmtContextImpl] ERROR: LoadKey called with invalid slot resource type";
        return score::Result<CryptoResourceGuard>{
            score::unexpect,
            MakeError(CryptoErrorCode::kInvalidArgument, "LoadKey called with invalid slot resource type")};
    }

    auto control_req_result = proto::ControlRequestBuilder()
                                  .forDataNodeId(m_context_id)
                                  .operation({actors::OP_ACTOR_KEY_MANAGEMENT, keymgmt_ops::KEY_LOAD})
                                  .with_in_val_uint64(slot.id)
                                  .build();

    if (!control_req_result.has_value())
    {
        score::mw::log::LogError() << "[API][KeyMgmtContextImpl] ERROR: Failed to build KEY_LOAD request";
        return score::Result<CryptoResourceGuard>{
            score::unexpect, MakeError(CryptoErrorCode::kInternalError, "Failed to build KEY_LOAD request")};
    }

    auto control_response_res = m_connection->SendRequest(control_req_result.value());

    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation({actors::OP_ACTOR_KEY_MANAGEMENT, keymgmt_ops::KEY_LOAD}).expectSuccess();

    if (!validator.isValid())
    {
        score::mw::log::LogError() << "[API][KeyMgmtContextImpl] ERROR:" << validator.getError();
        return score::Result<CryptoResourceGuard>{
            score::unexpect, MakeError(CryptoErrorCode::kInternalError, "KEY_LOAD daemon response invalid")};
    }

    // Extract the daemon-assigned resource id for the loaded key material
    auto resource_id_result = validator.getParameterAt<std::uint64_t>(0, 0);
    if (!resource_id_result.has_value())
    {
        score::mw::log::LogError() << "[API][KeyMgmtContextImpl] ERROR: KEY_LOAD response has invalid resource_id type";
        return score::Result<CryptoResourceGuard>{
            score::unexpect,
            MakeError(CryptoErrorCode::kInternalError, "KEY_LOAD response has invalid resource_id type")};
    }

    CryptoResourceId resource_id{};
    resource_id.id = resource_id_result.value();
    resource_id.type = ResourceType::kKey;
    resource_id.persistence = ResourcePersistence::kEphemeral;

    // Extract optional provider id from response (param 0, index 1)
    auto provider_result = validator.getParameterAt<std::uint16_t>(0, 1);
    if (provider_result.has_value())
    {
        resource_id.primary_provider = provider_result.value();
    }

    return CryptoResourceGuardFactory::Make(m_release_callback, resource_id);
}

// ---------------------------------------------------------------------------
// Key Material — Ephemeral
// ---------------------------------------------------------------------------

score::Result<CryptoResourceGuard> KeyManagementContextImpl::ImportKey(const ImportKeyParams& params)
{
    if (params.algorithm.empty() || params.algorithm.truncated() || params.key_data.empty() ||
        !params.key_data.data() ||
        static_cast<std::uint8_t>(params.format) > static_cast<std::uint8_t>(FormatType::kRaw) ||
        (static_cast<std::uint32_t>(params.permissions) & ~static_cast<std::uint32_t>(KeyOperationPermission::kAll)) !=
            0U)
    {
        return score::Result<CryptoResourceGuard>{score::unexpect, MakeError(CryptoErrorCode::kInvalidArgument)};
    }
    auto reply = ExchangeKeyOperation(proto::ControlRequestBuilder()
                                          .forDataNodeId(m_context_id)
                                          .operation({actors::OP_ACTOR_KEY_MANAGEMENT, keymgmt_ops::KEY_IMPORT})
                                          .with_in_string(params.algorithm)
                                          .with_in_data_buffer(params.key_data)
                                          .with_in_val_uint8(static_cast<std::uint8_t>(params.format))
                                          .with_in_val_uint32(static_cast<std::uint32_t>(params.permissions))
                                          .build(),
                                      2U);
    if (!reply.has_value())
    {
        return score::Result<CryptoResourceGuard>{score::unexpect, reply.error()};
    }
    return MakeKeyGuard(reply.value().parameters, 0U);
}

score::Result<std::size_t> KeyManagementContextImpl::GetExportKeySize(const CryptoResourceId& key, FormatType format)
{
    if (key.id == 0U || key.type != ResourceType::kKey ||
        static_cast<std::uint8_t>(format) > static_cast<std::uint8_t>(FormatType::kRaw))
    {
        return score::Result<std::size_t>{score::unexpect, MakeError(CryptoErrorCode::kInvalidArgument)};
    }
    auto reply = ExchangeKeyOperation(proto::ControlRequestBuilder()
                                          .forDataNodeId(m_context_id)
                                          .operation({actors::OP_ACTOR_KEY_MANAGEMENT, keymgmt_ops::KEY_GET_EXPORT_SIZE})
                                          .with_in_val_uint64(key.id)
                                          .with_in_val_uint8(static_cast<std::uint8_t>(format))
                                          .build(),
                                      1U);
    if (!reply.has_value())
    {
        return score::Result<std::size_t>{score::unexpect, reply.error()};
    }
    const auto* size = std::get_if<std::uint64_t>(&reply.value().parameters[0]);
    if (!size || *size > std::numeric_limits<std::size_t>::max())
    {
        return score::Result<std::size_t>{score::unexpect, MakeError(CryptoErrorCode::kOperationFailed)};
    }
    return static_cast<std::size_t>(*size);
}

score::Result<std::size_t> KeyManagementContextImpl::ExportKey(const CryptoResourceId& key,
                                                                score::cpp::span<uint8_t> output,
                                                                FormatType format)
{
    if (key.id == 0U || key.type != ResourceType::kKey || output.data() == nullptr ||
        static_cast<std::uint8_t>(format) > static_cast<std::uint8_t>(FormatType::kRaw))
    {
        return score::Result<std::size_t>{score::unexpect, MakeError(CryptoErrorCode::kInvalidArgument)};
    }
    auto reply = ExchangeKeyOperation(proto::ControlRequestBuilder()
                                          .forDataNodeId(m_context_id)
                                          .operation({actors::OP_ACTOR_KEY_MANAGEMENT, keymgmt_ops::KEY_EXPORT})
                                          .with_in_val_uint64(key.id)
                                          .with_in_val_uint8(static_cast<std::uint8_t>(format))
                                          .build(),
                                      1U);
    if (!reply.has_value())
    {
        return score::Result<std::size_t>{score::unexpect, reply.error()};
    }
    const auto* bytes = std::get_if<proto::OwnedBuffer>(&reply.value().parameters[0]);
    if (!bytes || bytes->size() > output.size())
    {
        return score::Result<std::size_t>{score::unexpect, MakeError(CryptoErrorCode::kInsufficientBufferSize)};
    }
    std::copy(bytes->begin(), bytes->end(), output.begin());
    return bytes->size();
}


// ---------------------------------------------------------------------------
// Stubs — not yet implemented
// ---------------------------------------------------------------------------
score::Result<std::monostate> KeyManagementContextImpl::GenerateKey(
    const CryptoResourceId& /*target_slot*/,
    const std::optional<CryptoResourceId>& /*public_slot*/,
    const GenerateKeyParams& /*params*/)
{
    score::mw::log::LogError() << "[API][KeyMgmtContextImpl] ERROR: GenerateKey with target_slot not yet implemented";
    return score::Result<std::monostate>{
        score::unexpect,
        MakeError(CryptoErrorCode::kUnsupportedOperation, "GenerateKey with target_slot not yet implemented")};
}

score::Result<CryptoResourceGuard> KeyManagementContextImpl::DeriveKey(const DeriveKeyParams& /*params*/)
{
    score::mw::log::LogError() << "[API][KeyMgmtContextImpl] ERROR: DeriveKey not yet implemented";
    return score::Result<CryptoResourceGuard>{
        score::unexpect, MakeError(CryptoErrorCode::kUnsupportedOperation, "DeriveKey not yet implemented")};
}

score::Result<std::monostate> KeyManagementContextImpl::DeriveKey(const CryptoResourceId& /*target_slot*/,
                                                                  const DeriveKeyParams& /*params*/)
{
    score::mw::log::LogError() << "[API][KeyMgmtContextImpl] ERROR: DeriveKey not yet implemented";
    return score::Result<std::monostate>{
        score::unexpect, MakeError(CryptoErrorCode::kUnsupportedOperation, "DeriveKey not yet implemented")};
}

score::Result<CryptoResourceGuard> KeyManagementContextImpl::AgreeKey(const AgreeKeyParams& /*params*/)
{
    score::mw::log::LogError() << "[API][KeyMgmtContextImpl] ERROR: AgreeKey not yet implemented";
    return score::Result<CryptoResourceGuard>{
        score::unexpect, MakeError(CryptoErrorCode::kUnsupportedOperation, "AgreeKey not yet implemented")};
}

score::Result<std::monostate> KeyManagementContextImpl::AgreeKey(const CryptoResourceId& /*target_slot*/,
                                                                 const AgreeKeyParams& /*params*/)
{
    score::mw::log::LogError() << "[API][KeyMgmtContextImpl] ERROR: AgreeKey not yet implemented";
    return score::Result<std::monostate>{
        score::unexpect, MakeError(CryptoErrorCode::kUnsupportedOperation, "AgreeKey not yet implemented")};
}

score::Result<std::monostate> KeyManagementContextImpl::PersistKey(const CryptoResourceId& /*target_slot*/,
                                                                   const CryptoResourceId& /*ephemeral_key*/)
{
    score::mw::log::LogError() << "[API][KeyMgmtContextImpl] ERROR: PersistKey not yet implemented";
    return score::Result<std::monostate>{
        score::unexpect, MakeError(CryptoErrorCode::kUnsupportedOperation, "PersistKey not yet implemented")};
}

score::Result<CryptoResourceGuard> KeyManagementContextImpl::UnwrapKey(const UnwrapKeyParams& /*params*/)
{
    score::mw::log::LogError() << "[API][KeyMgmtContextImpl] ERROR: UnwrapKey not yet implemented";
    return score::Result<CryptoResourceGuard>{
        score::unexpect, MakeError(CryptoErrorCode::kUnsupportedOperation, "UnwrapKey not yet implemented")};
}

score::Result<std::monostate> KeyManagementContextImpl::UnwrapKey(const CryptoResourceId& /*target_slot*/,
                                                                  const UnwrapKeyParams& /*params*/)
{
    score::mw::log::LogError() << "[API][KeyMgmtContextImpl] ERROR: UnwrapKey not yet implemented";
    return score::Result<std::monostate>{
        score::unexpect, MakeError(CryptoErrorCode::kUnsupportedOperation, "UnwrapKey not yet implemented")};
}

score::Result<std::monostate> KeyManagementContextImpl::ImportKey(const CryptoResourceId& /*target_slot*/,
                                                                  const ImportKeyParams& /*params*/)
{
    score::mw::log::LogError() << "[API][KeyMgmtContextImpl] ERROR: ImportKey not yet implemented";
    return score::Result<std::monostate>{
        score::unexpect, MakeError(CryptoErrorCode::kUnsupportedOperation, "ImportKey not yet implemented")};
}

score::Result<std::size_t> KeyManagementContextImpl::WrapKey(const WrapKeyParams& /*params*/,
                                                             score::cpp::span<uint8_t> /*output*/)
{
    score::mw::log::LogError() << "[API][KeyMgmtContextImpl] ERROR: WrapKey not yet implemented";
    return score::Result<std::size_t>{score::unexpect,
                                      MakeError(CryptoErrorCode::kUnsupportedOperation, "WrapKey not yet implemented")};
}

score::Result<std::size_t> KeyManagementContextImpl::GetWrapKeySize(const WrapKeyParams& /*params*/)
{
    score::mw::log::LogError() << "[API][KeyMgmtContextImpl] ERROR: GetWrapKeySize not yet implemented";
    return score::Result<std::size_t>{
        score::unexpect, MakeError(CryptoErrorCode::kUnsupportedOperation, "GetWrapKeySize not yet implemented")};
}

score::Result<std::monostate> KeyManagementContextImpl::ClearKey(const CryptoResourceId& /*key*/)
{
    score::mw::log::LogError() << "[API][KeyMgmtContextImpl] ERROR: ClearKey not yet implemented";
    return score::Result<std::monostate>{
        score::unexpect, MakeError(CryptoErrorCode::kUnsupportedOperation, "ClearKey not yet implemented")};
}

score::Result<KeySlotInfo> KeyManagementContextImpl::GetKeySlotInfo(const CryptoResourceId& /*slot*/)
{
    score::mw::log::LogError() << "[API][KeyMgmtContextImpl] ERROR: GetKeySlotInfo not yet implemented";
    return score::Result<KeySlotInfo>{
        score::unexpect, MakeError(CryptoErrorCode::kUnsupportedOperation, "GetKeySlotInfo not yet implemented")};
}

// ---------------------------------------------------------------------------
// KEM
// ---------------------------------------------------------------------------

score::Result<std::size_t> KeyManagementContextImpl::GetEncapsulationCiphertextSize(const EncapsulateKeyParams& params)
{
    auto valid = params.Validate();
    if (!valid.has_value())
    {
        return score::Result<std::size_t>{score::unexpect, valid.error()};
    }
    auto reply = ExchangeKeyOperation(proto::ControlRequestBuilder()
                                          .forDataNodeId(m_context_id)
                                          .operation({actors::OP_ACTOR_KEY_MANAGEMENT, keymgmt_ops::KEY_GET_ENCAPSULATION_SIZE})
                                          .with_in_string(params.algorithm)
                                          .with_in_val_uint64(params.peer_public_key.id)
                                          .build(),
                                      1U);
    if (!reply.has_value())
    {
        return score::Result<std::size_t>{score::unexpect, reply.error()};
    }
    const auto* size = std::get_if<std::uint64_t>(&reply.value().parameters[0]);
    if (!size || *size == 0U || *size > std::numeric_limits<std::size_t>::max())
    {
        return score::Result<std::size_t>{score::unexpect, MakeError(CryptoErrorCode::kOperationFailed)};
    }
    return static_cast<std::size_t>(*size);
}

score::Result<EncapsulationResult> KeyManagementContextImpl::EncapsulateKey(const EncapsulateKeyParams& params,
                                                                            score::cpp::span<uint8_t> ciphertext_out)
{
    auto valid = params.Validate();
    if (!valid.has_value())
    {
        return score::Result<EncapsulationResult>{score::unexpect, valid.error()};
    }
    if (ciphertext_out.empty() || ciphertext_out.data() == nullptr)
    {
        return score::Result<EncapsulationResult>{score::unexpect, MakeError(CryptoErrorCode::kInsufficientBufferSize)};
    }
    auto reply = ExchangeKeyOperation(proto::ControlRequestBuilder()
                                          .forDataNodeId(m_context_id)
                                          .operation({actors::OP_ACTOR_KEY_MANAGEMENT, keymgmt_ops::KEY_ENCAPSULATE})
                                          .with_in_string(params.algorithm)
                                          .with_in_val_uint64(params.peer_public_key.id)
                                          .with_in_val_uint64(ciphertext_out.size())
                                          .build(),
                                      3U);
    if (!reply.has_value())
    {
        return score::Result<EncapsulationResult>{score::unexpect, reply.error()};
    }
    // Construct the guard first so malformed ciphertext responses release a valid returned resource.
    auto guard = MakeKeyGuard(reply.value().parameters, 1U);
    if (!guard.has_value())
    {
        return score::Result<EncapsulationResult>{score::unexpect, guard.error()};
    }
    const auto* ciphertext = std::get_if<proto::OwnedBuffer>(&reply.value().parameters[0]);
    if (!ciphertext || ciphertext->empty() || ciphertext->size() > ciphertext_out.size())
    {
        return score::Result<EncapsulationResult>{score::unexpect, MakeError(CryptoErrorCode::kOperationFailed)};
    }
    std::copy(ciphertext->begin(), ciphertext->end(), ciphertext_out.begin());
    return EncapsulationResult{std::move(guard.value()), ciphertext->size()};
}

score::Result<CryptoResourceGuard> KeyManagementContextImpl::DecapsulateKey(const DecapsulateKeyParams& params)
{
    auto valid = params.Validate();
    if (!valid.has_value())
    {
        return score::Result<CryptoResourceGuard>{score::unexpect, valid.error()};
    }
    auto reply = ExchangeKeyOperation(proto::ControlRequestBuilder()
                                          .forDataNodeId(m_context_id)
                                          .operation({actors::OP_ACTOR_KEY_MANAGEMENT, keymgmt_ops::KEY_DECAPSULATE})
                                          .with_in_string(params.algorithm)
                                          .with_in_val_uint64(params.private_key.id)
                                          .with_in_data_buffer(params.ciphertext)
                                          .build(),
                                      2U);
    if (!reply.has_value())
    {
        return score::Result<CryptoResourceGuard>{score::unexpect, reply.error()};
    }
    return MakeKeyGuard(reply.value().parameters, 0U);
}

}  // namespace crypto

}  // namespace score

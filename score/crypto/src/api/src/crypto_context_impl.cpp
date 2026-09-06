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

#include "score/crypto/src/api/src/crypto_context_impl.hpp"

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/common/types.hpp"
#include "score/crypto/src/api/config/cipher_context_config.hpp"
#include "score/crypto/src/api/config/hash_context_config.hpp"
#include "score/crypto/src/api/config/key_management_context_config.hpp"
#include "score/crypto/src/api/config/mac_context_config.hpp"
#include "score/crypto/src/api/config/random_context_config.hpp"
#include "score/crypto/src/api/config/sign_context_config.hpp"
#include "score/crypto/src/api/config/verify_signature_context_config.hpp"
#include "score/crypto/src/api/contexts/src/cipher_context_impl.hpp"
#include "score/crypto/src/api/contexts/src/hash_context_impl.hpp"
#include "score/crypto/src/api/contexts/src/key_management_context_impl.hpp"
#include "score/crypto/src/api/contexts/src/mac_context_impl.hpp"
#include "score/crypto/src/api/contexts/src/random_context_impl.hpp"
#include "score/crypto/src/api/contexts/src/sign_context_impl.hpp"
#include "score/crypto/src/api/contexts/src/verify_signature_context_impl.hpp"
#include "score/crypto/src/api/src/provider_type_converter.hpp"
#include "score/crypto/src/daemon/common/context_types.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"

#include "score/crypto/src/api/control_plane/i_connection.hpp"
#include "score/result/result.h"

#include "score/mw/log/logging.h"
#include <cstdint>

#include <memory>
#include <utility>

// Full definitions needed for Result<unique_ptr<T>> return types
#include "score/crypto/src/api/contexts/i_cipher_context.hpp"
#include "score/crypto/src/api/contexts/i_hash_context.hpp"
#include "score/crypto/src/api/contexts/i_key_management_context.hpp"
#include "score/crypto/src/api/contexts/i_mac_context.hpp"
#include "score/crypto/src/api/contexts/i_random_context.hpp"
#include "score/crypto/src/api/contexts/i_sign_context.hpp"
#include "score/crypto/src/api/contexts/i_verify_signature_context.hpp"
#include "score/crypto/src/api/objects/i_key_object.hpp"
#include "score/crypto/src/api/objects/i_key_slot_object.hpp"

#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"

#include <optional>
#include <string_view>

namespace score
{

namespace crypto
{

/// The context-type ids are owned by the daemon side, which dispatches on them.
namespace daemon_common = ::score::crypto::daemon::common;

namespace
{

/// @brief Describes one CTX_CREATE call on the wire.
///
/// Wire layout is positional and shared by every context type:
///   [0] context_type, [1] algorithm, [2] provider_type (or no-param),
///   [3] key_node_id (keyed contexts only), [4] mode byte (cipher direction
///   or MAC/signature OperationMode).
struct ContextCreationRequest
{
    std::string_view context_type{};
    const AlgorithmId* algorithm{nullptr};
    std::optional<ProviderType> provider_type{std::nullopt};
    std::optional<std::uint64_t> key_node_id{std::nullopt};
    std::optional<std::uint8_t> mode{std::nullopt};
};

/// @brief Sends CTX_CREATE to the daemon and returns the new context's node id.
///
/// Centralises the request/validate/extract sequence that is identical for all
/// context types, so each factory below only has to describe its parameters and
/// wrap the resulting id in the right context implementation.
score::Result<std::uint64_t> CreateDaemonContext(
    const std::shared_ptr<score::crypto::api::control_plane::IConnection>& connection,
    const ContextCreationRequest& request)
{
    namespace proto = ::score::crypto::daemon::control_plane::protocol;

    auto builder = proto::ControlRequestBuilder()
                       .forDataNodeId(connection->GetConnectionNodeId())
                       .operation(score::crypto::daemon::mediator::operations::CreateContext())
                       .with_in_string(request.context_type)
                       .with_in_string(*request.algorithm);

    if (request.provider_type.has_value())
    {
        builder = builder.with_in_val_uint8(ProviderTypeConverter::ToWireValue(request.provider_type.value()));
    }
    else
    {
        builder = builder.with_no_param();
    }

    if (request.key_node_id.has_value())
    {
        builder = builder.with_in_val_uint64(request.key_node_id.value());
    }

    if (request.mode.has_value())
    {
        builder = builder.with_in_val_uint8(request.mode.value());
    }

    auto control_req_result = builder.build();
    if (!control_req_result.has_value())
    {
        score::mw::log::LogError() << "[API][CryptoContextImpl] ERROR: Failed to build CTX_CREATE request for"
                                   << request.context_type;
        return score::Result<std::uint64_t>{
            score::unexpect, MakeError(CryptoErrorCode::kContextCreationFailed, "Failed to build CTX_CREATE request")};
    }

    auto control_response_res = connection->SendRequest(control_req_result.value());

    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation(score::crypto::daemon::mediator::operations::CreateContext()).expectSuccess();

    if (!validator.isValid())
    {
        score::mw::log::LogError() << "[API][CryptoContextImpl] ERROR:" << validator.getError();
        // Forward the daemon's own verdict when it gave one — a key whose policy
        // forbids this context must surface as kKeyOperationNotPermitted, which
        // the caller can act on, rather than a generic creation failure.
        return score::Result<std::uint64_t>{
            score::unexpect,
            MakeError(validator.getOperationError().value_or(CryptoErrorCode::kContextCreationFailed),
                      "CTX_CREATE daemon response invalid")};
    }

    auto ctx_id_result = validator.getParameterAt<std::uint64_t>(0, 0);
    if (!ctx_id_result.has_value())
    {
        score::mw::log::LogError() << "[API][CryptoContextImpl] ERROR: CTX_CREATE response has invalid context_id type";
        return score::Result<std::uint64_t>{
            score::unexpect,
            MakeError(CryptoErrorCode::kContextCreationFailed, "CTX_CREATE response has invalid context_id type")};
    }

    return ctx_id_result.value();
}

/// @brief Rejects a key handle that cannot drive a keyed operation context.
score::Result<std::monostate> ValidateOperationKey(const CryptoResourceId& key, std::string_view context_type)
{
    if (key.id == 0U)
    {
        score::mw::log::LogError() << "[API][CryptoContextImpl] ERROR: " << context_type << " invalid / missing key id";
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kContextCreationFailed, "invalid / missing key id")};
    }

    if ((key.type != ResourceType::kKey) && (key.type != ResourceType::kKeySlot))
    {
        score::mw::log::LogError() << "[API][CryptoContextImpl] ERROR: " << context_type << " invalid key type";
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kUnsupportedOperation, "invalid key resource type")};
    }

    return std::monostate{};
}

}  // namespace

CryptoContextImpl::CryptoContextImpl(std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
                                     std::shared_ptr<IBufferTranscoder> transcoder)
    : m_connection(std::move(connection)), m_transcoder(std::move(transcoder))
{
}

CryptoContextImpl::~CryptoContextImpl() {}

// ---------------------------------------------------------------------------
// Context Factory — Hash
// ---------------------------------------------------------------------------

score::Result<std::unique_ptr<IHashContext>> CryptoContextImpl::CreateHashContext(const HashContextConfig& config)
{
    namespace proto = ::score::crypto::daemon::control_plane::protocol;

    // Send CTX_CREATE to the daemon to create a server-side hash context.
    // The daemon will validate the algorithm and return the context_id and digest_size.
    auto request_builder = proto::ControlRequestBuilder()
                               .forDataNodeId(m_connection->GetConnectionNodeId())
                               .operation(score::crypto::daemon::mediator::operations::CreateContext())
                               .with_in_string(daemon_common::context_types::kHash)
                               .with_in_string(config.algorithm);

    if (config.provider_type.has_value())
    {
        request_builder =
            request_builder.with_in_val_uint8(ProviderTypeConverter::ToWireValue(config.provider_type.value()));
    }
    else
    {
        request_builder = request_builder.with_no_param();
    }

    auto control_req_result = request_builder.build();
    if (!control_req_result.has_value())
    {
        return score::Result<std::unique_ptr<IHashContext>>{
            score::unexpect, MakeError(CryptoErrorCode::kContextCreationFailed, "Failed to build CTX_CREATE request")};
    }

    // Send CTX_CREATE request to daemon
    auto control_response_res = m_connection->SendRequest(control_req_result.value());

    // Validate CTX_CREATE response
    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation(score::crypto::daemon::mediator::operations::CreateContext()).expectSuccess();

    if (!validator.isValid())
    {
        return score::Result<std::unique_ptr<IHashContext>>{
            score::unexpect, MakeError(CryptoErrorCode::kContextCreationFailed, "CTX_CREATE daemon response invalid")};
    }

    auto ctx_id_result = validator.getParameterAt<std::uint64_t>(0, 0);
    if (!ctx_id_result.has_value())
    {
        return score::Result<std::unique_ptr<IHashContext>>{
            score::unexpect,
            MakeError(CryptoErrorCode::kContextCreationFailed, "CTX_CREATE response has invalid context_id type")};
    }

    const uint64_t context_id = ctx_id_result.value();
    auto hash_ctx = std::make_unique<HashContextImpl>(m_connection, context_id, config.algorithm, m_transcoder);

    return hash_ctx;
}

// ---------------------------------------------------------------------------
// Resource Resolution
// ---------------------------------------------------------------------------

score::Result<CryptoResourceId> CryptoContextImpl::ResolveResource(const ResourceId& resource_id, ResourceType type)
{
    namespace proto = ::score::crypto::daemon::control_plane::protocol;

    auto control_req_result = proto::ControlRequestBuilder()
                                  .forDataNodeId(m_connection->GetConnectionNodeId())
                                  .operation(score::crypto::daemon::mediator::operations::ResolveResource())
                                  .with_in_string(resource_id)
                                  .with_in_val_uint8(static_cast<std::uint8_t>(type))
                                  .build();

    if (!control_req_result.has_value())
    {
        return score::Result<CryptoResourceId>{
            score::unexpect, MakeError(CryptoErrorCode::kInternalError, "Failed to build RESOURCE_RESOLVE request")};
    }

    auto control_response_res = m_connection->SendRequest(control_req_result.value());

    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation(score::crypto::daemon::mediator::operations::ResolveResource()).expectSuccess();

    if (!validator.isValid())
    {
        return score::Result<CryptoResourceId>{
            score::unexpect, MakeError(CryptoErrorCode::kInternalError, "RESOURCE_RESOLVE daemon response invalid")};
    }

    auto id_result = validator.getParameterAt<std::uint64_t>(0, 0);
    if (!id_result.has_value())
    {
        return score::Result<CryptoResourceId>{
            score::unexpect,
            MakeError(CryptoErrorCode::kInternalError, "RESOURCE_RESOLVE response missing resource_id")};
    }

    auto type_result = validator.getParameterAt<std::uint8_t>(0, 1);
    if (!type_result.has_value())
    {
        return score::Result<CryptoResourceId>{
            score::unexpect, MakeError(CryptoErrorCode::kInternalError, "RESOURCE_RESOLVE response missing type")};
    }

    auto persistence_result = validator.getParameterAt<bool>(0, 2);
    if (!persistence_result.has_value())
    {
        return score::Result<CryptoResourceId>{
            score::unexpect,
            MakeError(CryptoErrorCode::kInternalError, "RESOURCE_RESOLVE response missing persistence")};
    }

    auto primary_provider = validator.getParameterAt<std::uint16_t>(0, 3);
    if (!primary_provider.has_value())
    {
        return score::Result<CryptoResourceId>{
            score::unexpect,
            MakeError(CryptoErrorCode::kInternalError, "RESOURCE_RESOLVE response missing primary_provider")};
    }

    CryptoResourceId resolved{};
    resolved.id = id_result.value();
    resolved.type = static_cast<ResourceType>(type_result.value());
    resolved.persistence =
        persistence_result.value() ? ResourcePersistence::kPersistent : ResourcePersistence::kEphemeral;
    resolved.primary_provider = primary_provider.value();

    return resolved;
}

// ---------------------------------------------------------------------------
// Context Factory stubs — not yet implemented
// ---------------------------------------------------------------------------

score::Result<std::unique_ptr<IMacContext>> CryptoContextImpl::CreateMacContext(const MacContextConfig& config)
{
    auto key_check = ValidateOperationKey(config.key, "CreateMacContext");
    if (!key_check.has_value())
    {
        return score::Result<std::unique_ptr<IMacContext>>{score::unexpect, key_check.error()};
    }

    ContextCreationRequest request{};
    request.context_type = daemon_common::context_types::kMac;
    request.algorithm = &config.algorithm;
    request.provider_type = config.provider_type;
    request.key_node_id = config.key.id;
    // Routes the daemon to C_Sign* or C_Verify* (EVP_MAC either way for OpenSSL).
    request.mode = static_cast<std::uint8_t>(config.operation_mode);

    auto context_id = CreateDaemonContext(m_connection, request);
    if (!context_id.has_value())
    {
        return score::Result<std::unique_ptr<IMacContext>>{score::unexpect, context_id.error()};
    }

    return std::make_unique<MacContextImpl>(m_connection, context_id.value(), config.algorithm, m_transcoder);
}

score::Result<std::unique_ptr<IKeyManagementContext>> CryptoContextImpl::CreateKeyManagementContext(
    const KeyManagementContextConfig& config)
{
    namespace proto = ::score::crypto::daemon::control_plane::protocol;

    // Send CTX_CREATE to the daemon to create a server-side key management context.
    auto request_builder = proto::ControlRequestBuilder()
                               .forDataNodeId(m_connection->GetConnectionNodeId())
                               .operation(score::crypto::daemon::mediator::operations::CreateContext())
                               .with_in_string(daemon_common::context_types::kKeyManagement)
                               .with_in_string("");  // no algorithm for key management

    if (config.provider_type.has_value())
    {
        request_builder =
            request_builder.with_in_val_uint8(ProviderTypeConverter::ToWireValue(config.provider_type.value()));
    }
    else
    {
        request_builder = request_builder.with_no_param();
    }

    auto control_req_result = request_builder.build();
    if (!control_req_result.has_value())
    {
        return score::Result<std::unique_ptr<IKeyManagementContext>>{
            score::unexpect,
            MakeError(CryptoErrorCode::kContextCreationFailed, "Failed to build CTX_CREATE request for KEY_MGMT")};
    }

    auto control_response_res = m_connection->SendRequest(control_req_result.value());

    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation(score::crypto::daemon::mediator::operations::CreateContext()).expectSuccess();

    if (!validator.isValid())
    {
        return score::Result<std::unique_ptr<IKeyManagementContext>>{
            score::unexpect,
            MakeError(CryptoErrorCode::kContextCreationFailed, "CTX_CREATE KEY_MGMT daemon response invalid")};
    }

    auto ctx_id_result = validator.getParameterAt<std::uint64_t>(0, 0);
    if (!ctx_id_result.has_value())
    {
        return score::Result<std::unique_ptr<IKeyManagementContext>>{
            score::unexpect,
            MakeError(CryptoErrorCode::kContextCreationFailed,
                      "CTX_CREATE KEY_MGMT response has invalid context_id type")};
    }

    const uint64_t context_id = ctx_id_result.value();
    auto key_mgmt_ctx = std::make_unique<KeyManagementContextImpl>(m_connection, context_id);

    return key_mgmt_ctx;
}

// ---------------------------------------------------------------------------
// Context Factory — Cipher / Sign / Verify / Random
// ---------------------------------------------------------------------------

score::Result<std::unique_ptr<ICipherContext>> CryptoContextImpl::CreateCipherContext(const CipherContextConfig& config)
{
    auto key_check = ValidateOperationKey(config.key, "CreateCipherContext");
    if (!key_check.has_value())
    {
        return score::Result<std::unique_ptr<ICipherContext>>{score::unexpect, key_check.error()};
    }

    ContextCreationRequest request{};
    request.context_type = daemon_common::context_types::kCipher;
    request.algorithm = &config.algorithm;
    request.provider_type = config.provider_type;
    request.key_node_id = config.key.id;
    // The daemon routes to EVP_EncryptInit / EVP_DecryptInit (or C_EncryptInit /
    // C_DecryptInit) based on this byte.
    request.mode = static_cast<std::uint8_t>(config.direction);

    auto context_id = CreateDaemonContext(m_connection, request);
    if (!context_id.has_value())
    {
        return score::Result<std::unique_ptr<ICipherContext>>{score::unexpect, context_id.error()};
    }

    return std::make_unique<CipherContextImpl>(m_connection, context_id.value(), config.algorithm, m_transcoder);
}

score::Result<std::unique_ptr<ISignContext>> CryptoContextImpl::CreateSignContext(const SignContextConfig& config)
{
    auto key_check = ValidateOperationKey(config.key, "CreateSignContext");
    if (!key_check.has_value())
    {
        return score::Result<std::unique_ptr<ISignContext>>{score::unexpect, key_check.error()};
    }

    ContextCreationRequest request{};
    request.context_type = daemon_common::context_types::kSign;
    request.algorithm = &config.algorithm;
    request.provider_type = config.provider_type;
    request.key_node_id = config.key.id;
    // A signing context always uses the private half of the key pair, regardless
    // of what the caller left in BaseContextConfig::operation_mode.
    request.mode = static_cast<std::uint8_t>(OperationMode::kGenerate);

    auto context_id = CreateDaemonContext(m_connection, request);
    if (!context_id.has_value())
    {
        return score::Result<std::unique_ptr<ISignContext>>{score::unexpect, context_id.error()};
    }

    return std::make_unique<SignContextImpl>(m_connection, context_id.value(), config.algorithm, m_transcoder);
}

score::Result<std::unique_ptr<IVerifySignatureContext>> CryptoContextImpl::CreateVerifySignatureContext(
    const VerifySignatureContextConfig& config)
{
    auto key_check = ValidateOperationKey(config.key, "CreateVerifySignatureContext");
    if (!key_check.has_value())
    {
        return score::Result<std::unique_ptr<IVerifySignatureContext>>{score::unexpect, key_check.error()};
    }

    ContextCreationRequest request{};
    request.context_type = daemon_common::context_types::kVerify;
    request.algorithm = &config.algorithm;
    request.provider_type = config.provider_type;
    request.key_node_id = config.key.id;
    // Signals the daemon to bind the public half of the key pair.
    request.mode = static_cast<std::uint8_t>(OperationMode::kVerify);

    auto context_id = CreateDaemonContext(m_connection, request);
    if (!context_id.has_value())
    {
        return score::Result<std::unique_ptr<IVerifySignatureContext>>{score::unexpect, context_id.error()};
    }

    return std::make_unique<VerifySignatureContextImpl>(
        m_connection, context_id.value(), config.algorithm, m_transcoder);
}

score::Result<std::unique_ptr<IRandomContext>> CryptoContextImpl::CreateRandomContext(const RandomContextConfig& config)
{
    // No key and no mode byte: an RNG context is keyless, so the wire call stops
    // after the provider-type slot.
    ContextCreationRequest request{};
    request.context_type = daemon_common::context_types::kRandom;
    request.algorithm = &config.algorithm;
    request.provider_type = config.provider_type;

    auto context_id = CreateDaemonContext(m_connection, request);
    if (!context_id.has_value())
    {
        return score::Result<std::unique_ptr<IRandomContext>>{score::unexpect, context_id.error()};
    }

    return std::make_unique<RandomContextImpl>(m_connection, context_id.value(), config.algorithm, m_transcoder);
}

// ---------------------------------------------------------------------------
// Queries (TODO)
// ---------------------------------------------------------------------------

score::Result<AlgorithmCapabilities> CryptoContextImpl::QueryCapabilities(const AlgorithmId& /*algorithm*/)
{
    // TODO: Implement algorithm capability query via daemon IPC
    return score::Result<AlgorithmCapabilities>{
        score::unexpect,
        MakeError(CryptoErrorCode::kUnsupportedOperation, "QueryCapabilities(algorithm) not yet implemented")};
}

score::Result<SystemCapabilities> CryptoContextImpl::QueryCapabilities()
{
    // TODO: Implement system capability query via daemon IPC
    return score::Result<SystemCapabilities>{
        score::unexpect, MakeError(CryptoErrorCode::kUnsupportedOperation, "QueryCapabilities() not yet implemented")};
}

score::Result<ProviderInfo> CryptoContextImpl::GetProviderInfo(uint16_t /*provider_id*/)
{
    // TODO: Implement provider info query via daemon IPC
    return score::Result<ProviderInfo>{
        score::unexpect, MakeError(CryptoErrorCode::kUnsupportedOperation, "GetProviderInfo not yet implemented")};
}

score::Result<ProviderInfo> CryptoContextImpl::GetProviderInfo(const CryptoResourceId& /*resourceId*/)
{
    // TODO: Implement provider info query via daemon IPC
    return score::Result<ProviderInfo>{
        score::unexpect, MakeError(CryptoErrorCode::kUnsupportedOperation, "GetProviderInfo not yet implemented")};
}

// ---------------------------------------------------------------------------
// Typed Object Access (TODO)
// ---------------------------------------------------------------------------

score::Result<std::unique_ptr<IKeyObject>> CryptoContextImpl::GetKeyObject(const CryptoResourceId& /*id*/)
{
    // TODO: Implement key object retrieval via daemon IPC
    return score::Result<std::unique_ptr<IKeyObject>>{
        score::unexpect, MakeError(CryptoErrorCode::kUnsupportedOperation, "GetKeyObject not yet implemented")};
}

score::Result<std::unique_ptr<IKeySlotObject>> CryptoContextImpl::GetKeySlotObject(const CryptoResourceId& /*id*/)
{
    // TODO: Implement key slot object retrieval via daemon IPC
    return score::Result<std::unique_ptr<IKeySlotObject>>{
        score::unexpect, MakeError(CryptoErrorCode::kUnsupportedOperation, "GetKeySlotObject not yet implemented")};
}

}  // namespace crypto

}  // namespace score

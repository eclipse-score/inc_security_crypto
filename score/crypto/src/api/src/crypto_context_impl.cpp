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
#include "score/crypto/src/api/config/trust_store_management_context_config.hpp"
#include "score/crypto/src/api/contexts/src/cert_management_context_impl.hpp"
#include "score/crypto/src/api/contexts/src/cert_verification_context_impl.hpp"
#include "score/crypto/src/api/contexts/src/trust_store_management_context_impl.hpp"
#include "score/crypto/src/api/src/provider_type_converter.hpp"
#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/common/context_mode.hpp"
#include "score/crypto/src/daemon/common/context_types.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/provider/cert_management/cert_management_operations.hpp"

#include "score/crypto/src/api/control_plane/i_connection.hpp"
#include "score/result/result.h"

#include "score/mw/log/logging.h"
#include <algorithm>
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
#include "score/crypto/src/api/config/certificate_context_config.hpp"
#include "score/crypto/src/api/config/certificate_verification_context_config.hpp"
#include "score/crypto/src/api/contexts/i_certificate_management_context.hpp"
#include "score/crypto/src/api/contexts/i_certificate_verification_context.hpp"
#include "score/crypto/src/api/objects/i_cert_slot_object.hpp"
#include "score/crypto/src/api/objects/i_certificate_object.hpp"
#include "score/crypto/src/api/objects/i_key_object.hpp"
#include "score/crypto/src/api/objects/i_key_slot_object.hpp"
#include "score/crypto/src/api/objects/i_trust_store_object.hpp"
#include "score/crypto/src/api/objects/src/trust_store_object_impl.hpp"

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
///   [3] key_node_id (keyed contexts only), [4] daemon_common::ContextMode,
///   [5] CipherPadding (cipher contexts only).
struct ContextCreationRequest
{
    std::string_view context_type{};
    /// Null for a context type that names no algorithm, which the daemon reads
    /// as the empty string in slot [1]. KEY_MANAGEMENT is the only such type.
    const AlgorithmId* algorithm{nullptr};
    std::optional<ProviderType> provider_type{std::nullopt};
    std::optional<std::uint64_t> key_node_id{std::nullopt};
    std::optional<daemon_common::ContextMode> mode{std::nullopt};
    std::optional<CipherPadding> padding{std::nullopt};
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

    auto builder =
        proto::ControlRequestBuilder()
            .forDataNodeId(connection->GetConnectionNodeId())
            .operation(score::crypto::daemon::mediator::operations::CreateContext())
            .with_in_string(request.context_type)
            .with_in_string(request.algorithm != nullptr ? std::string_view{*request.algorithm} : std::string_view{});

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
        builder = builder.with_in_val_uint8(static_cast<std::uint8_t>(request.mode.value()));
    }

    if (request.padding.has_value())
    {
        builder = builder.with_in_val_uint8(static_cast<std::uint8_t>(request.padding.value()));
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
    ContextCreationRequest request{};
    request.context_type = daemon_common::context_types::kHash;
    request.algorithm = &config.algorithm;
    request.provider_type = config.provider_type;

    auto context_id = CreateDaemonContext(m_connection, request);
    if (!context_id.has_value())
    {
        return score::Result<std::unique_ptr<IHashContext>>{score::unexpect, context_id.error()};
    }

    return std::make_unique<HashContextImpl>(m_connection, context_id.value(), config.algorithm, m_transcoder);
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
                                  .with_in_val_uint64(static_cast<std::uint64_t>(type))
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
    request.mode = daemon_common::ToContextMode(config.operation_mode);

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
    // No algorithm: a key management context is not bound to one, and no key is
    // bound at creation either — its operations carry their own key references.
    ContextCreationRequest request{};
    request.context_type = daemon_common::context_types::kKeyManagement;
    request.provider_type = config.provider_type;

    auto context_id = CreateDaemonContext(m_connection, request);
    if (!context_id.has_value())
    {
        return score::Result<std::unique_ptr<IKeyManagementContext>>{score::unexpect, context_id.error()};
    }

    return std::make_unique<KeyManagementContextImpl>(m_connection, context_id.value());
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
    request.mode = daemon_common::ToContextMode(config.direction);
    request.padding = config.padding;

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
    request.mode = daemon_common::ToContextMode(OperationMode::kGenerate);

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
    request.mode = daemon_common::ToContextMode(OperationMode::kVerify);

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
// Context Factory — Certificate Management
// ---------------------------------------------------------------------------

score::Result<std::unique_ptr<ICertificateManagementContext>> CryptoContextImpl::CreateCertificateManagementContext(
    const CertificateContextConfig& config)
{
    namespace proto = ::score::crypto::daemon::control_plane::protocol;

    proto::ControlRequestBuilder builder{};
    builder.forDataNodeId(m_connection->GetConnectionNodeId())
        .operation(score::crypto::daemon::mediator::operations::CreateContext())
        .with_in_string("CERT:MANAGEMENT")
        .with_in_string("");  // no algorithm for cert management

    if (config.provider_type.has_value())
        builder.with_in_val_uint8(ProviderTypeConverter::ToWireValue(config.provider_type.value()));
    else
        builder.with_no_param();

    auto req = builder.build();
    if (!req.has_value())
        return score::Result<std::unique_ptr<ICertificateManagementContext>>{
            score::unexpect,
            MakeError(CryptoErrorCode::kContextCreationFailed, "Failed to build CTX_CREATE for CERT:MANAGEMENT")};

    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(score::crypto::daemon::mediator::operations::CreateContext()).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::unique_ptr<ICertificateManagementContext>>{
            score::unexpect,
            MakeError(CryptoErrorCode::kContextCreationFailed, "CERT:MANAGEMENT CTX_CREATE response invalid")};

    auto ctx_id_res = validator.getParameterAt<std::uint64_t>(0, 0);
    if (!ctx_id_res.has_value())
        return score::Result<std::unique_ptr<ICertificateManagementContext>>{
            score::unexpect,
            MakeError(CryptoErrorCode::kContextCreationFailed, "CERT:MANAGEMENT CTX_CREATE missing context_id")};

    return std::make_unique<CertManagementContextImpl>(m_connection, ctx_id_res.value(), m_transcoder);
}

// ---------------------------------------------------------------------------
// Context Factory — Certificate Verification
// ---------------------------------------------------------------------------

score::Result<std::unique_ptr<ICertificateVerificationContext>> CryptoContextImpl::CreateCertificateVerificationContext(
    const CertificateVerificationContextConfig& config)
{
    namespace proto = ::score::crypto::daemon::control_plane::protocol;

    proto::ControlRequestBuilder builder{};
    builder.forDataNodeId(m_connection->GetConnectionNodeId())
        .operation(score::crypto::daemon::mediator::operations::CreateContext())
        .with_in_string("CERT:VERIFICATION")
        .with_in_string("");  // no algorithm

    if (config.provider_type.has_value())
        builder.with_in_val_uint8(ProviderTypeConverter::ToWireValue(config.provider_type.value()));
    else
        builder.with_no_param();

    auto req = builder.build();
    if (!req.has_value())
        return score::Result<std::unique_ptr<ICertificateVerificationContext>>{
            score::unexpect,
            MakeError(CryptoErrorCode::kContextCreationFailed, "Failed to build CTX_CREATE for CERT:VERIFICATION")};

    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(score::crypto::daemon::mediator::operations::CreateContext()).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::unique_ptr<ICertificateVerificationContext>>{
            score::unexpect,
            MakeError(CryptoErrorCode::kContextCreationFailed, "CERT:VERIFICATION CTX_CREATE response invalid")};

    auto ctx_id_res = validator.getParameterAt<std::uint64_t>(0, 0);
    if (!ctx_id_res.has_value())
        return score::Result<std::unique_ptr<ICertificateVerificationContext>>{
            score::unexpect,
            MakeError(CryptoErrorCode::kContextCreationFailed, "CERT:VERIFICATION CTX_CREATE missing context_id")};

    auto context = std::make_unique<CertVerificationContextImpl>(m_connection, ctx_id_res.value(), m_transcoder);
    if (config.revocation_policy.has_value())
    {
        auto policy_result = context->SetRevocationCheckPolicy(*config.revocation_policy);
        if (!policy_result.has_value())
            return score::Result<std::unique_ptr<ICertificateVerificationContext>>{score::unexpect,
                                                                                   policy_result.error()};
    }
    auto coverage_result = context->SetRevocationCoveragePolicy(config.revocation_coverage_policy);
    if (!coverage_result.has_value())
        return score::Result<std::unique_ptr<ICertificateVerificationContext>>{score::unexpect,
                                                                               coverage_result.error()};
    return std::unique_ptr<ICertificateVerificationContext>{std::move(context)};
}

// ---------------------------------------------------------------------------
// Context Factory — Trust-Store Management
// ---------------------------------------------------------------------------

score::Result<std::unique_ptr<ITrustStoreManagementContext>> CryptoContextImpl::CreateTrustStoreManagementContext(
    const TrustStoreManagementContextConfig& config)
{
    namespace proto = ::score::crypto::daemon::control_plane::protocol;

    proto::ControlRequestBuilder builder{};
    builder.forDataNodeId(m_connection->GetConnectionNodeId())
        .operation(score::crypto::daemon::mediator::operations::CreateContext())
        .with_in_string("CERT:TRUST_STORE")
        .with_in_string("");  // no algorithm for trust-store management

    if (config.provider_type.has_value())
        builder.with_in_val_uint8(ProviderTypeConverter::ToWireValue(config.provider_type.value()));
    else
        builder.with_no_param();

    auto req = builder.build();
    if (!req.has_value())
        return score::Result<std::unique_ptr<ITrustStoreManagementContext>>{
            score::unexpect,
            MakeError(CryptoErrorCode::kContextCreationFailed, "Failed to build CTX_CREATE for CERT:TRUST_STORE")};

    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(score::crypto::daemon::mediator::operations::CreateContext()).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::unique_ptr<ITrustStoreManagementContext>>{
            score::unexpect,
            MakeError(CryptoErrorCode::kContextCreationFailed, "CERT:TRUST_STORE CTX_CREATE response invalid")};

    auto ctx_id_res = validator.getParameterAt<std::uint64_t>(0, 0);
    if (!ctx_id_res.has_value())
        return score::Result<std::unique_ptr<ITrustStoreManagementContext>>{
            score::unexpect,
            MakeError(CryptoErrorCode::kContextCreationFailed, "CERT:TRUST_STORE CTX_CREATE missing context_id")};

    return std::make_unique<TrustStoreManagementContextImpl>(m_connection, ctx_id_res.value(), m_transcoder);
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

score::Result<std::unique_ptr<ICertificateObject>> CryptoContextImpl::GetCertificateObject(const CryptoResourceId& id)
{
    namespace proto = ::score::crypto::daemon::control_plane::protocol;
    namespace med_ops = ::score::crypto::daemon::mediator::operations;

    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_connection->GetConnectionNodeId())
                   .operation(med_ops::GetCertificateObject())
                   .with_in_val_uint64(id.id)
                   .build();
    if (!req.has_value())
        return score::Result<std::unique_ptr<ICertificateObject>>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "GetCertificateObject: build failed")};

    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(med_ops::GetCertificateObject()).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::unique_ptr<ICertificateObject>>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};

    auto sub_res = validator.getParameterAt<daemon::common::OwnedString>(0, 0);
    auto iss_res = validator.getParameterAt<daemon::common::OwnedString>(0, 1);
    auto nb_res = validator.getParameterAt<std::uint64_t>(0, 2);
    auto na_res = validator.getParameterAt<std::uint64_t>(0, 3);
    auto ca_res = validator.getParameterAt<std::uint8_t>(0, 4);
    // params 5 (skid) and 6 (akid) are not used by the view-only object
    auto serial_res = validator.getParameterAt<daemon::common::OwnedString>(0, 7);
    auto fp_res = validator.getParameterAt<daemon::common::OwnedBuffer>(0, 8);
    auto has_crl_res = validator.getParameterAt<std::uint8_t>(0, 9);
    auto crl_fp_res = validator.getParameterAt<daemon::common::OwnedBuffer>(0, 10);
    auto crl_issuer_fp_res = validator.getParameterAt<daemon::common::OwnedBuffer>(0, 11);
    auto crl_this_update_res = validator.getParameterAt<std::uint64_t>(0, 12);
    auto crl_next_update_res = validator.getParameterAt<std::uint64_t>(0, 13);
    auto crl_number_res = validator.getParameterAt<std::uint64_t>(0, 14);

    if (!sub_res.has_value() || !iss_res.has_value() || !nb_res.has_value() || !na_res.has_value() ||
        !ca_res.has_value() || !has_crl_res.has_value() || !crl_fp_res.has_value() || !crl_issuer_fp_res.has_value() ||
        !crl_this_update_res.has_value() || !crl_next_update_res.has_value() || !crl_number_res.has_value())
        return score::Result<std::unique_ptr<ICertificateObject>>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "GetCertificateObject: response incomplete")};

    std::string serial = serial_res.has_value() ? std::move(serial_res.value()) : std::string{};
    std::array<uint8_t, 32U> fingerprint{};
    if (fp_res.has_value() && fp_res.value().size() == 32U)
        std::copy(fp_res.value().begin(), fp_res.value().end(), fingerprint.begin());

    std::optional<CrlMetadata> crl_metadata;
    if (has_crl_res.value() != 0U)
    {
        if (crl_fp_res.value().size() != 32U || crl_issuer_fp_res.value().size() != 32U)
            return score::Result<std::unique_ptr<ICertificateObject>>{
                score::unexpect,
                MakeError(CryptoErrorCode::kOperationFailed, "GetCertificateObject: invalid CRL metadata")};
        CrlMetadata metadata;
        std::copy(crl_fp_res.value().begin(), crl_fp_res.value().end(), metadata.fingerprint.begin());
        std::copy(
            crl_issuer_fp_res.value().begin(), crl_issuer_fp_res.value().end(), metadata.issuer_fingerprint.begin());
        metadata.this_update = static_cast<int64_t>(crl_this_update_res.value());
        metadata.next_update = static_cast<int64_t>(crl_next_update_res.value());
        metadata.crl_number = crl_number_res.value();
        crl_metadata = metadata;
    }

    return std::unique_ptr<ICertificateObject>{new CertificateObjectImpl(id,
                                                                         std::move(sub_res.value()),
                                                                         std::move(iss_res.value()),
                                                                         std::move(serial),
                                                                         fingerprint,
                                                                         static_cast<int64_t>(nb_res.value()),
                                                                         static_cast<int64_t>(na_res.value()),
                                                                         ca_res.value() != 0U,
                                                                         std::move(crl_metadata))};
}

score::Result<std::unique_ptr<ICertSlotObject>> CryptoContextImpl::GetCertSlotObject(const CryptoResourceId& id)
{
    namespace proto = ::score::crypto::daemon::control_plane::protocol;
    namespace med_ops = ::score::crypto::daemon::mediator::operations;

    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_connection->GetConnectionNodeId())
                   .operation(med_ops::GetCertSlotObject())
                   .with_in_val_uint64(id.id)
                   .build();
    if (!req.has_value())
        return score::Result<std::unique_ptr<ICertSlotObject>>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "GetCertSlotObject: build failed")};

    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(med_ops::GetCertSlotObject()).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::unique_ptr<ICertSlotObject>>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};

    auto state_res = validator.getParameterAt<std::uint8_t>(0, 0);
    auto has_crl_res = validator.getParameterAt<std::uint8_t>(0, 1);
    if (!state_res.has_value() || !has_crl_res.has_value() ||
        state_res.value() > static_cast<std::uint8_t>(CertificateSlotState::kLocked) || has_crl_res.value() > 1U)
        return score::Result<std::unique_ptr<ICertSlotObject>>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "GetCertSlotObject: invalid slot info")};

    const CertificateSlotInfo info{static_cast<CertificateSlotState>(state_res.value()), has_crl_res.value() != 0U};
    return std::unique_ptr<ICertSlotObject>{new CertSlotObjectImpl(id, info)};
}

score::Result<std::unique_ptr<ITrustStoreObject>> CryptoContextImpl::GetTrustStoreObject(const CryptoResourceId& id)
{
    namespace proto = ::score::crypto::daemon::control_plane::protocol;
    namespace med_ops = ::score::crypto::daemon::mediator::operations;

    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_connection->GetConnectionNodeId())
                   .operation(med_ops::GetTrustStoreObject())
                   .with_in_val_uint64(id.id)
                   .build();
    if (!req.has_value())
        return score::Result<std::unique_ptr<ITrustStoreObject>>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "GetTrustStoreObject: build failed")};

    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(med_ops::GetTrustStoreObject()).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::unique_ptr<ITrustStoreObject>>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};

    auto count_res = validator.getParameterAt<std::uint64_t>(0, 0);
    if (!count_res.has_value())
        return score::Result<std::unique_ptr<ITrustStoreObject>>{
            score::unexpect,
            MakeError(CryptoErrorCode::kOperationFailed, "GetTrustStoreObject: response missing count")};

    const std::size_t count = static_cast<std::size_t>(count_res.value());
    std::vector<MemberInfo> members{};
    members.reserve(count);

    // Per-member layout (7 params each, base = 1 + i*7):
    //   base+0: slot_node_id (uint64), base+1: fingerprint (OwnedBuffer 32B),
    //   base+2: subject (OwnedString), base+3: issuer (OwnedString),
    //   base+4: serial_number (OwnedString), base+5: kind (uint8), base+6: status (uint8)
    for (std::size_t i = 0U; i < count; ++i)
    {
        const int base = static_cast<int>(1U + i * 7U);
        auto nid_res = validator.getParameterAt<std::uint64_t>(0, base);
        auto fp_res = validator.getParameterAt<daemon::common::OwnedBuffer>(0, base + 1);
        auto sub_res = validator.getParameterAt<daemon::common::OwnedString>(0, base + 2);
        auto iss_res = validator.getParameterAt<daemon::common::OwnedString>(0, base + 3);
        auto serial_res = validator.getParameterAt<daemon::common::OwnedString>(0, base + 4);
        auto kind_res = validator.getParameterAt<std::uint8_t>(0, base + 5);
        auto status_res = validator.getParameterAt<std::uint8_t>(0, base + 6);

        if (!nid_res.has_value() || !fp_res.has_value() || !kind_res.has_value() || !status_res.has_value() ||
            status_res.value() > static_cast<std::uint8_t>(MemberStatus::kAwaitingAcknowledgement))
            return score::Result<std::unique_ptr<ITrustStoreObject>>{
                score::unexpect,
                MakeError(CryptoErrorCode::kOperationFailed, "GetTrustStoreObject: incomplete member entry")};

        MemberInfo info{};
        info.slot_id.id = nid_res.value();
        info.slot_id.type = ResourceType::kCertSlot;
        info.slot_id.persistence = ResourcePersistence::kPersistent;
        info.slot_id.primary_provider = 0U;  // provider not included in snapshot
        const auto& fp_buf = fp_res.value();
        const std::size_t copy_len = std::min(fp_buf.size(), info.sha256_fingerprint.size());
        std::copy_n(fp_buf.begin(), copy_len, info.sha256_fingerprint.begin());
        if (sub_res.has_value())
            info.subject = std::move(sub_res.value());
        if (iss_res.has_value())
            info.issuer = std::move(iss_res.value());
        if (serial_res.has_value())
            info.serial_number = std::move(serial_res.value());
        info.kind = static_cast<MemberKind>(kind_res.value());
        info.status = static_cast<MemberStatus>(status_res.value());
        members.push_back(std::move(info));
    }

    return std::unique_ptr<ITrustStoreObject>{new TrustStoreObjectImpl(id, std::move(members))};
}

}  // namespace crypto

}  // namespace score

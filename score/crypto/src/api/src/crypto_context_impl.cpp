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
#include "score/crypto/src/api/config/certificate_context_config.hpp"
#include "score/crypto/src/api/config/cipher_context_config.hpp"
#include "score/crypto/src/api/config/hash_context_config.hpp"
#include "score/crypto/src/api/config/key_management_context_config.hpp"
#include "score/crypto/src/api/config/mac_context_config.hpp"
#include "score/crypto/src/api/config/random_context_config.hpp"
#include "score/crypto/src/api/config/sign_context_config.hpp"
#include "score/crypto/src/api/config/trust_store_management_context_config.hpp"
#include "score/crypto/src/api/config/verify_signature_context_config.hpp"
#include "score/crypto/src/api/contexts/src/cert_management_context_impl.hpp"
#include "score/crypto/src/api/contexts/src/cipher_context_impl.hpp"
#include "score/crypto/src/api/contexts/src/hash_context_impl.hpp"
#include "score/crypto/src/api/contexts/src/key_management_context_impl.hpp"
#include "score/crypto/src/api/contexts/src/mac_context_impl.hpp"
#include "score/crypto/src/api/contexts/src/random_context_impl.hpp"
#include "score/crypto/src/api/contexts/src/sign_context_impl.hpp"
#include "score/crypto/src/api/contexts/src/trust_store_management_context_impl.hpp"
#include "score/crypto/src/api/contexts/src/verify_signature_context_impl.hpp"
#include "score/crypto/src/api/objects/src/cert_slot_object_impl.hpp"
#include "score/crypto/src/api/objects/src/certificate_object_impl.hpp"
#include "score/crypto/src/api/objects/src/trust_store_object_impl.hpp"
#include "score/crypto/src/api/src/provider_type_converter.hpp"
#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/common/context/context_mode.hpp"
#include "score/crypto/src/daemon/common/context/context_types.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"

#include "score/crypto/src/api/control_plane/i_connection.hpp"
#include "score/result/result.h"

#include "score/mw/log/logging.h"
#include <cstdint>

#include <memory>
#include <utility>

// Full definitions needed for Result<unique_ptr<T>> return types
#include "score/crypto/src/api/contexts/i_certificate_management_context.hpp"
#include "score/crypto/src/api/contexts/i_cipher_context.hpp"
#include "score/crypto/src/api/contexts/i_hash_context.hpp"
#include "score/crypto/src/api/contexts/i_key_management_context.hpp"
#include "score/crypto/src/api/contexts/i_mac_context.hpp"
#include "score/crypto/src/api/contexts/i_random_context.hpp"
#include "score/crypto/src/api/contexts/i_sign_context.hpp"
#include "score/crypto/src/api/contexts/i_trust_store_management_context.hpp"
#include "score/crypto/src/api/contexts/i_verify_signature_context.hpp"
#include "score/crypto/src/api/objects/i_cert_slot_object.hpp"
#include "score/crypto/src/api/objects/i_certificate_object.hpp"
#include "score/crypto/src/api/objects/i_key_object.hpp"
#include "score/crypto/src/api/objects/i_key_slot_object.hpp"
#include "score/crypto/src/api/objects/i_trust_store_object.hpp"

#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

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
///   [5] CipherPadding (cipher contexts only; no-param for signature contexts),
///   [6] SignatureInputMode (signature contexts only).
struct ContextCreationRequest
{
    std::string_view context_type{};
    /// Null for a context type that names no algorithm, which the daemon reads
    /// as the empty string in slot [1]. KEY:MANAGEMENT, CERT:MANAGEMENT and
    /// CERT:TRUST_STORE are such types.
    const AlgorithmId* algorithm{nullptr};
    std::optional<ProviderType> provider_type{std::nullopt};
    std::optional<std::uint64_t> key_node_id{std::nullopt};
    std::optional<daemon_common::ContextMode> mode{std::nullopt};
    std::optional<CipherPadding> padding{std::nullopt};
    std::optional<SignatureInputMode> signature_input_mode{std::nullopt};
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
    else
    {
        builder = builder.with_no_param();
    }

    if (request.mode.has_value())
    {
        builder = builder.with_in_val_uint8(static_cast<std::uint8_t>(request.mode.value()));
    }
    else
    {
        builder = builder.with_no_param();
    }

    if (request.padding.has_value())
    {
        builder = builder.with_in_val_uint8(static_cast<std::uint8_t>(request.padding.value()));
    }
    else
    {
        builder = builder.with_no_param();
    }

    if (request.signature_input_mode.has_value())
    {
        builder = builder.with_in_val_uint8(static_cast<std::uint8_t>(request.signature_input_mode.value()));
    }
    else
    {
        builder = builder.with_no_param();
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
    if (config.provider.has_value())
    {
        score::mw::log::LogError()
            << "[API][CryptoContextImpl] ERROR: Explicit provider resources are not supported for hash contexts";
        return score::Result<std::unique_ptr<IHashContext>>{
            score::unexpect,
            MakeError(CryptoErrorCode::kUnsupportedOperation,
                      "Explicit provider resource selection is not supported for hash contexts")};
    }

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

    return std::make_unique<KeyManagementContextImpl>(m_connection, context_id.value(), m_transcoder);
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
    request.signature_input_mode = config.input_mode;

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
    request.signature_input_mode = config.input_mode;

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

score::Result<std::unique_ptr<ICertificateManagementContext>> CryptoContextImpl::CreateCertificateManagementContext(
    const CertificateContextConfig& config)
{
    // No algorithm: certificate management contexts are not bound to one. The null pointer is sent as an
    // empty string, which the daemon accepts for the CERT scope.
    ContextCreationRequest request{};
    request.context_type = daemon_common::context_types::kCertManagement;
    request.provider_type = config.provider_type;

    auto context_id = CreateDaemonContext(m_connection, request);
    if (!context_id.has_value())
    {
        return score::Result<std::unique_ptr<ICertificateManagementContext>>{score::unexpect, context_id.error()};
    }

    return std::make_unique<CertManagementContextImpl>(m_connection, context_id.value(), m_transcoder);
}

score::Result<std::unique_ptr<ITrustStoreManagementContext>> CryptoContextImpl::CreateTrustStoreManagementContext(
    const TrustStoreManagementContextConfig& config)
{
    // No algorithm: trust-store management contexts are not bound to one, so the algorithm slot carries the empty
    // string. The daemon serves the context from the CERT:TRUST_STORE scope.
    ContextCreationRequest request{};
    request.context_type = daemon_common::context_types::kCertTrustStore;
    request.provider_type = config.provider_type;

    auto context_id = CreateDaemonContext(m_connection, request);
    if (!context_id.has_value())
    {
        return score::Result<std::unique_ptr<ITrustStoreManagementContext>>{score::unexpect, context_id.error()};
    }

    return std::make_unique<TrustStoreManagementContextImpl>(m_connection, context_id.value(), m_transcoder);
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

// ---------------------------------------------------------------------------
// Certificate Object Access
// ---------------------------------------------------------------------------

namespace
{

// Parameter indices of the GET_CERTIFICATE_OBJECT response. The daemon defines the layout in
// BuildCertObjectResponse; these constants must stay in step with it.
inline constexpr std::size_t kCertSubjectIdx = 0U;
inline constexpr std::size_t kCertIssuerIdx = 1U;
inline constexpr std::size_t kCertNotBeforeIdx = 2U;
inline constexpr std::size_t kCertNotAfterIdx = 3U;
inline constexpr std::size_t kCertSerialIdx = 7U;
inline constexpr std::size_t kCertFingerprintIdx = 8U;
inline constexpr std::size_t kCertHasCrlIdx = 9U;
inline constexpr std::size_t kCertCrlFingerprintIdx = 10U;
inline constexpr std::size_t kCertCrlIssuerFingerprintIdx = 11U;
inline constexpr std::size_t kCertCrlThisUpdateIdx = 12U;
inline constexpr std::size_t kCertCrlNextUpdateIdx = 13U;
inline constexpr std::size_t kCertCrlNumberIdx = 14U;
inline constexpr std::size_t kCertSpkiSizeIdx = 15U;
inline constexpr std::size_t kCertPublicKeyAlgorithmIdx = 16U;

// Parameter indices of the GET_CERT_SLOT_OBJECT response (BuildCertSlotInfoResponse on the daemon).
inline constexpr std::size_t kSlotStateIdx = 0U;
inline constexpr std::size_t kSlotHasCrlIdx = 1U;

/// @brief Reads a SHA-256 field. Fails when the parameter is absent, mistyped, or not 32 bytes.
template <typename Validator>
bool ReadFingerprint(Validator& validator, std::size_t idx, std::array<std::uint8_t, kSha256FingerprintSize>& out)
{
    auto buffer = validator.template getParameterAt<daemon_common::OwnedBuffer>(0U, idx);
    if (!buffer.has_value() || buffer.value().size() != kSha256FingerprintSize)
    {
        return false;
    }
    std::copy(buffer.value().begin(), buffer.value().end(), out.begin());
    return true;
}

/// @brief Reads the CRL fields of a GET_CERTIFICATE_OBJECT response. Called only when has_crl is set.
template <typename Validator>
std::optional<CrlMetadata> ReadCrlMetadata(Validator& validator)
{
    CrlMetadata metadata{};
    auto this_update = validator.template getParameterAt<std::uint64_t>(0U, kCertCrlThisUpdateIdx);
    auto next_update = validator.template getParameterAt<std::uint64_t>(0U, kCertCrlNextUpdateIdx);
    auto crl_number = validator.template getParameterAt<std::uint64_t>(0U, kCertCrlNumberIdx);
    const bool fingerprints_ok = ReadFingerprint(validator, kCertCrlFingerprintIdx, metadata.fingerprint) &&
                                 ReadFingerprint(validator, kCertCrlIssuerFingerprintIdx, metadata.issuer_fingerprint);
    if (!fingerprints_ok || !this_update.has_value() || !next_update.has_value() || !crl_number.has_value())
    {
        return std::nullopt;
    }
    metadata.this_update = static_cast<std::int64_t>(this_update.value());
    metadata.next_update = static_cast<std::int64_t>(next_update.value());
    metadata.crl_number = crl_number.value();
    return metadata;
}

// Parameter indices of the GET_TRUST_STORE_MEMBER_ID_LIST response (BuildTrustStoreMemberIdListResponse).
inline constexpr std::size_t kTrustStoreMemberCountIdx = 0U;
inline constexpr std::size_t kTrustStoreFirstMemberIdx = 1U;

// Parameter indices of the GET_TRUST_STORE_MEMBER_OBJECT response (BuildTrustStoreMemberObjectResponse).
inline constexpr std::size_t kTrustStoreMemberSlotIdx = 0U;
inline constexpr std::size_t kTrustStoreMemberFingerprintIdx = 1U;
inline constexpr std::size_t kTrustStoreMemberSubjectIdx = 2U;
inline constexpr std::size_t kTrustStoreMemberIssuerIdx = 3U;
inline constexpr std::size_t kTrustStoreMemberSerialIdx = 4U;
inline constexpr std::size_t kTrustStoreMemberKindIdx = 5U;
inline constexpr std::size_t kTrustStoreMemberStatusIdx = 6U;

/// @brief Reads a GET_TRUST_STORE_MEMBER_OBJECT response. Fails when a field is absent, mistyped, out of range, or
///        the fingerprint is not 32 bytes.
template <typename Validator>
std::optional<MemberInfo> ReadTrustStoreMember(Validator& validator)
{
    auto slot_node_id = validator.template getParameterAt<std::uint64_t>(0U, kTrustStoreMemberSlotIdx);
    auto subject = validator.template getParameterAt<daemon_common::OwnedString>(0U, kTrustStoreMemberSubjectIdx);
    auto issuer = validator.template getParameterAt<daemon_common::OwnedString>(0U, kTrustStoreMemberIssuerIdx);
    auto serial = validator.template getParameterAt<daemon_common::OwnedString>(0U, kTrustStoreMemberSerialIdx);
    auto kind = validator.template getParameterAt<std::uint8_t>(0U, kTrustStoreMemberKindIdx);
    auto status = validator.template getParameterAt<std::uint8_t>(0U, kTrustStoreMemberStatusIdx);
    constexpr auto kMaxKind = static_cast<std::uint8_t>(MemberKind::kConditionalExternal);
    constexpr auto kMaxStatus = static_cast<std::uint8_t>(MemberStatus::kAwaitingAcknowledgement);
    if (!slot_node_id.has_value() || !subject.has_value() || !issuer.has_value() || !serial.has_value() ||
        !kind.has_value() || kind.value() > kMaxKind || !status.has_value() || status.value() > kMaxStatus)
    {
        return std::nullopt;
    }

    MemberInfo member{};
    if (!ReadFingerprint(validator, kTrustStoreMemberFingerprintIdx, member.sha256_fingerprint))
    {
        return std::nullopt;
    }
    member.slot_id.id = slot_node_id.value();
    member.slot_id.type = ResourceType::kCertSlot;
    member.slot_id.persistence = ResourcePersistence::kPersistent;
    member.slot_id.primary_provider = 0U;  // the member snapshot does not carry the provider
    member.subject = std::move(subject.value());
    member.issuer = std::move(issuer.value());
    member.serial_number = std::move(serial.value());
    member.kind = static_cast<MemberKind>(kind.value());
    member.status = static_cast<MemberStatus>(status.value());
    return member;
}

}  // namespace

score::Result<std::unique_ptr<ICertificateObject>> CryptoContextImpl::GetCertificateObject(const CryptoResourceId& id)
{
    namespace proto = ::score::crypto::daemon::control_plane::protocol;
    namespace med_ops = ::score::crypto::daemon::mediator::operations;
    using ResultType = score::Result<std::unique_ptr<ICertificateObject>>;

    if ((id.type != ResourceType::kCertificate) && (id.type != ResourceType::kCertSlot))
    {
        return ResultType{score::unexpect,
                          MakeError(CryptoErrorCode::kInvalidArgument,
                                    "GetCertificateObject requires a certificate or certificate slot")};
    }

    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_connection->GetConnectionNodeId())
                   .operation(med_ops::GetCertificateObject())
                   .with_in_val_uint64(id.id)
                   .build();
    if (!req.has_value())
    {
        return ResultType{
            score::unexpect,
            MakeError(CryptoErrorCode::kOperationFailed, "GetCertificateObject: failed to build request")};
    }

    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(med_ops::GetCertificateObject()).expectSuccess();
    if (!validator.isValid())
    {
        return ResultType{
            score::unexpect,
            MakeError(validator.getOperationError().value_or(CryptoErrorCode::kOperationFailed), validator.getError())};
    }

    auto subject = validator.getParameterAt<daemon_common::OwnedString>(0U, kCertSubjectIdx);
    auto issuer = validator.getParameterAt<daemon_common::OwnedString>(0U, kCertIssuerIdx);
    auto serial = validator.getParameterAt<daemon_common::OwnedString>(0U, kCertSerialIdx);
    auto not_before = validator.getParameterAt<std::uint64_t>(0U, kCertNotBeforeIdx);
    auto not_after = validator.getParameterAt<std::uint64_t>(0U, kCertNotAfterIdx);
    auto has_crl = validator.getParameterAt<std::uint8_t>(0U, kCertHasCrlIdx);
    auto spki_size = validator.getParameterAt<std::uint64_t>(0U, kCertSpkiSizeIdx);
    auto spki_algorithm = validator.getParameterAt<daemon_common::OwnedString>(0U, kCertPublicKeyAlgorithmIdx);
    std::array<std::uint8_t, kSha256FingerprintSize> fingerprint{};
    const bool fingerprint_ok = ReadFingerprint(validator, kCertFingerprintIdx, fingerprint);
    if (!subject.has_value() || !issuer.has_value() || !serial.has_value() || !not_before.has_value() ||
        !not_after.has_value() || !has_crl.has_value() || has_crl.value() > 1U || !fingerprint_ok ||
        !spki_size.has_value() || !spki_algorithm.has_value())
    {
        return ResultType{score::unexpect,
                          MakeError(CryptoErrorCode::kOperationFailed, "GetCertificateObject: response incomplete")};
    }

    std::optional<CrlMetadata> crl_metadata{};
    if (has_crl.value() == 1U)
    {
        crl_metadata = ReadCrlMetadata(validator);
        if (!crl_metadata.has_value())
        {
            return ResultType{
                score::unexpect,
                MakeError(CryptoErrorCode::kOperationFailed, "GetCertificateObject: CRL metadata incomplete")};
        }
    }

    return std::make_unique<CertificateObjectImpl>(id,
                                                   std::move(subject.value()),
                                                   std::move(issuer.value()),
                                                   std::move(serial.value()),
                                                   fingerprint,
                                                   static_cast<std::int64_t>(not_before.value()),
                                                   static_cast<std::int64_t>(not_after.value()),
                                                   crl_metadata,
                                                   m_connection,
                                                   m_transcoder,
                                                   static_cast<std::size_t>(spki_size.value()),
                                                   std::move(spki_algorithm.value()));
}

score::Result<std::unique_ptr<ICertSlotObject>> CryptoContextImpl::GetCertSlotObject(const CryptoResourceId& id)
{
    namespace proto = ::score::crypto::daemon::control_plane::protocol;
    namespace med_ops = ::score::crypto::daemon::mediator::operations;
    using ResultType = score::Result<std::unique_ptr<ICertSlotObject>>;

    if (id.type != ResourceType::kCertSlot)
    {
        return ResultType{
            score::unexpect,
            MakeError(CryptoErrorCode::kInvalidArgument, "GetCertSlotObject requires a certificate slot")};
    }

    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_connection->GetConnectionNodeId())
                   .operation(med_ops::GetCertSlotObject())
                   .with_in_val_uint64(id.id)
                   .build();
    if (!req.has_value())
    {
        return ResultType{score::unexpect,
                          MakeError(CryptoErrorCode::kOperationFailed, "GetCertSlotObject: failed to build request")};
    }

    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(med_ops::GetCertSlotObject()).expectSuccess();
    if (!validator.isValid())
    {
        return ResultType{
            score::unexpect,
            MakeError(validator.getOperationError().value_or(CryptoErrorCode::kOperationFailed), validator.getError())};
    }

    auto state = validator.getParameterAt<std::uint8_t>(0U, kSlotStateIdx);
    auto has_crl = validator.getParameterAt<std::uint8_t>(0U, kSlotHasCrlIdx);
    constexpr auto kMaxState = static_cast<std::uint8_t>(CertificateSlotState::kLocked);
    if (!state.has_value() || !has_crl.has_value() || state.value() > kMaxState || has_crl.value() > 1U)
    {
        return ResultType{score::unexpect,
                          MakeError(CryptoErrorCode::kOperationFailed, "GetCertSlotObject: invalid slot info")};
    }

    const CertificateSlotInfo info{static_cast<CertificateSlotState>(state.value()), has_crl.value() == 1U};
    return std::make_unique<CertSlotObjectImpl>(id, info);
}

score::Result<std::unique_ptr<ITrustStoreObject>> CryptoContextImpl::GetTrustStoreObject(const CryptoResourceId& id)
{
    namespace proto = ::score::crypto::daemon::control_plane::protocol;
    namespace med_ops = ::score::crypto::daemon::mediator::operations;
    using ResultType = score::Result<std::unique_ptr<ITrustStoreObject>>;

    if (id.type != ResourceType::kCertificateTrustStore)
    {
        return ResultType{
            score::unexpect,
            MakeError(CryptoErrorCode::kInvalidArgument, "GetTrustStoreObject requires a certificate trust store")};
    }

    // Member identities only. Each response stays bounded regardless of how many members the store holds.
    auto id_list_req = proto::ControlRequestBuilder()
                           .forDataNodeId(m_connection->GetConnectionNodeId())
                           .operation(med_ops::GetTrustStoreMemberIdList())
                           .with_in_val_uint64(id.id)
                           .build();
    if (!id_list_req.has_value())
    {
        return ResultType{score::unexpect,
                          MakeError(CryptoErrorCode::kOperationFailed,
                                    "GetTrustStoreObject: failed to build member id list request")};
    }

    auto id_list_resp = m_connection->SendRequest(id_list_req.value());
    auto id_list_validator = proto::ControlResponseValidator::FromResult(id_list_resp);
    id_list_validator.expectOperation(med_ops::GetTrustStoreMemberIdList()).expectSuccess();
    if (!id_list_validator.isValid())
    {
        return ResultType{score::unexpect,
                          MakeError(id_list_validator.getOperationError().value_or(CryptoErrorCode::kOperationFailed),
                                    id_list_validator.getError())};
    }

    auto count_res = id_list_validator.getParameterAt<std::uint64_t>(0U, kTrustStoreMemberCountIdx);
    if (!count_res.has_value())
    {
        return ResultType{
            score::unexpect,
            MakeError(CryptoErrorCode::kOperationFailed, "GetTrustStoreObject: member id list response missing count")};
    }

    const auto count = static_cast<std::size_t>(count_res.value());
    std::vector<std::uint64_t> slot_node_ids{};
    for (std::size_t i = 0U; i < count; ++i)
    {
        auto nid_res = id_list_validator.getParameterAt<std::uint64_t>(0U, kTrustStoreFirstMemberIdx + i);
        if (!nid_res.has_value())
        {
            return ResultType{
                score::unexpect,
                MakeError(CryptoErrorCode::kOperationFailed, "GetTrustStoreObject: member id list entry missing")};
        }
        slot_node_ids.push_back(nid_res.value());
    }

    // One member-detail request per listed slot.
    std::vector<MemberInfo> members{};
    for (const auto slot_node_id : slot_node_ids)
    {
        auto member_req = proto::ControlRequestBuilder()
                              .forDataNodeId(m_connection->GetConnectionNodeId())
                              .operation(med_ops::GetTrustStoreMemberObject())
                              .with_in_val_uint64(id.id)
                              .with_in_val_uint64(slot_node_id)
                              .build();
        if (!member_req.has_value())
        {
            return ResultType{
                score::unexpect,
                MakeError(CryptoErrorCode::kOperationFailed, "GetTrustStoreObject: failed to build member request")};
        }

        auto member_resp = m_connection->SendRequest(member_req.value());
        auto member_validator = proto::ControlResponseValidator::FromResult(member_resp);
        member_validator.expectOperation(med_ops::GetTrustStoreMemberObject()).expectSuccess();
        if (!member_validator.isValid())
        {
            return ResultType{
                score::unexpect,
                MakeError(member_validator.getOperationError().value_or(CryptoErrorCode::kOperationFailed),
                          member_validator.getError())};
        }

        auto member = ReadTrustStoreMember(member_validator);
        if (!member.has_value())
        {
            return ResultType{
                score::unexpect,
                MakeError(CryptoErrorCode::kOperationFailed, "GetTrustStoreObject: member response incomplete")};
        }
        members.push_back(std::move(member.value()));
    }

    return std::make_unique<TrustStoreObjectImpl>(id, std::move(members));
}

}  // namespace crypto

}  // namespace score

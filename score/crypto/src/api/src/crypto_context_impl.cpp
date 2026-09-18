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
#include "score/crypto/src/api/config/hash_context_config.hpp"
#include "score/crypto/src/api/config/key_management_context_config.hpp"
#include "score/crypto/src/api/config/mac_context_config.hpp"
#include "score/crypto/src/api/config/trust_store_management_context_config.hpp"
#include "score/crypto/src/api/contexts/src/cert_management_context_impl.hpp"
#include "score/crypto/src/api/contexts/src/cert_verification_context_impl.hpp"
#include "score/crypto/src/api/contexts/src/hash_context_impl.hpp"
#include "score/crypto/src/api/contexts/src/key_management_context_impl.hpp"
#include "score/crypto/src/api/contexts/src/mac_context_impl.hpp"
#include "score/crypto/src/api/contexts/src/trust_store_management_context_impl.hpp"
#include "score/crypto/src/api/src/provider_type_converter.hpp"
#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
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
#include "score/crypto/src/api/config/certificate_context_config.hpp"
#include "score/crypto/src/api/config/certificate_verification_context_config.hpp"
#include "score/crypto/src/api/contexts/i_certificate_management_context.hpp"
#include "score/crypto/src/api/contexts/i_certificate_verification_context.hpp"
#include "score/crypto/src/api/contexts/i_hash_context.hpp"
#include "score/crypto/src/api/contexts/i_key_management_context.hpp"
#include "score/crypto/src/api/contexts/i_mac_context.hpp"
#include "score/crypto/src/api/objects/i_cert_slot_object.hpp"
#include "score/crypto/src/api/objects/i_certificate_object.hpp"
#include "score/crypto/src/api/objects/i_key_object.hpp"
#include "score/crypto/src/api/objects/i_key_slot_object.hpp"
#include "score/crypto/src/api/objects/i_trust_store_object.hpp"
#include "score/crypto/src/api/objects/src/trust_store_object_impl.hpp"

#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"

namespace score
{

namespace crypto
{

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
                               .with_in_string("HASH")
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
    namespace proto = ::score::crypto::daemon::control_plane::protocol;

    if (config.key.id == 0)
    {
        return score::Result<std::unique_ptr<IMacContext>>{
            score::unexpect,
            MakeError(CryptoErrorCode::kContextCreationFailed, "CreateMacContext invalid / missing key id")};
    }

    if (config.key.type != ResourceType::kKey && config.key.type != ResourceType::kKeySlot)
    {
        return score::Result<std::unique_ptr<IMacContext>>{
            score::unexpect, MakeError(CryptoErrorCode::kUnsupportedOperation, "CreateMacContext invalid key type")};
    }

    // Send CTX_CREATE to the daemon to create a server-side MAC context.
    // MAC context requires: context type "MAC", algorithm, and key id.
    auto request_builder = proto::ControlRequestBuilder()
                               .forDataNodeId(m_connection->GetConnectionNodeId())
                               .operation(score::crypto::daemon::mediator::operations::CreateContext())
                               .with_in_string("MAC")
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

    request_builder = request_builder.with_in_val_uint64(config.key.id);

    // Serialize operation_mode (param[4]) so the daemon can route to C_Sign* or C_Verify*.
    request_builder = request_builder.with_in_val_uint8(static_cast<std::uint8_t>(config.operation_mode));

    auto control_req_result = request_builder.build();
    if (!control_req_result.has_value())
    {
        return score::Result<std::unique_ptr<IMacContext>>{
            score::unexpect,
            MakeError(CryptoErrorCode::kContextCreationFailed, "Failed to build CTX_CREATE request for MAC")};
    }

    // Send CTX_CREATE request to daemon
    auto control_response_res = m_connection->SendRequest(control_req_result.value());

    // Validate CTX_CREATE response
    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation(score::crypto::daemon::mediator::operations::CreateContext()).expectSuccess();

    if (!validator.isValid())
    {
        return score::Result<std::unique_ptr<IMacContext>>{
            score::unexpect,
            MakeError(CryptoErrorCode::kContextCreationFailed, "CTX_CREATE MAC daemon response invalid")};
    }

    auto ctx_id_result = validator.getParameterAt<std::uint64_t>(0, 0);
    if (!ctx_id_result.has_value())
    {
        return score::Result<std::unique_ptr<IMacContext>>{
            score::unexpect,
            MakeError(CryptoErrorCode::kContextCreationFailed, "CTX_CREATE MAC response has invalid context_id type")};
    }

    const uint64_t context_id = ctx_id_result.value();
    auto mac_ctx = std::make_unique<MacContextImpl>(m_connection, context_id, config.algorithm, m_transcoder);

    return mac_ctx;
}

score::Result<std::unique_ptr<IKeyManagementContext>> CryptoContextImpl::CreateKeyManagementContext(
    const KeyManagementContextConfig& config)
{
    namespace proto = ::score::crypto::daemon::control_plane::protocol;

    // Send CTX_CREATE to the daemon to create a server-side key management context.
    auto request_builder = proto::ControlRequestBuilder()
                               .forDataNodeId(m_connection->GetConnectionNodeId())
                               .operation(score::crypto::daemon::mediator::operations::CreateContext())
                               .with_in_string("KEY_MANAGEMENT")
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

    return std::make_unique<CertManagementContextImpl>(m_connection, ctx_id_res.value());
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

    return std::make_unique<CertVerificationContextImpl>(m_connection, ctx_id_res.value());
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

    return std::make_unique<TrustStoreManagementContextImpl>(m_connection, ctx_id_res.value());
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
    if (!state_res.has_value() || !has_crl_res.has_value())
        return score::Result<std::unique_ptr<ICertSlotObject>>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "GetCertSlotObject: response missing state")};

    const bool is_occupied = (static_cast<CertificateSlotState>(state_res.value()) == CertificateSlotState::kOccupied);
    return std::unique_ptr<ICertSlotObject>{new CertSlotObjectImpl(id, is_occupied, has_crl_res.value() != 0U)};
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
    //   base+4: serial_number (OwnedString), base+5: kind (uint8), base+6: is_enabled (uint8)
    for (std::size_t i = 0U; i < count; ++i)
    {
        const int base = static_cast<int>(1U + i * 7U);
        auto nid_res = validator.getParameterAt<std::uint64_t>(0, base);
        auto fp_res = validator.getParameterAt<daemon::common::OwnedBuffer>(0, base + 1);
        auto sub_res = validator.getParameterAt<daemon::common::OwnedString>(0, base + 2);
        auto iss_res = validator.getParameterAt<daemon::common::OwnedString>(0, base + 3);
        auto serial_res = validator.getParameterAt<daemon::common::OwnedString>(0, base + 4);
        auto kind_res = validator.getParameterAt<std::uint8_t>(0, base + 5);
        auto enabled_res = validator.getParameterAt<std::uint8_t>(0, base + 6);

        if (!nid_res.has_value() || !fp_res.has_value() || !kind_res.has_value() || !enabled_res.has_value())
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
        info.is_enabled = (enabled_res.value() != 0U);
        members.push_back(std::move(info));
    }

    return std::unique_ptr<ITrustStoreObject>{new TrustStoreObjectImpl(id, std::move(members))};
}

}  // namespace crypto

}  // namespace score

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

#include "score/crypto/src/api/contexts/src/trust_store_management_context_impl.hpp"

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/common/src/i_release_callback.hpp"
#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_management_operations.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"

#include "score/mw/log/logging.h"
#include "score/result/result.h"

#include <cstdint>
#include <memory>
#include <utility>

namespace score
{

namespace crypto
{

namespace proto = ::score::crypto::daemon::control_plane::protocol;
namespace actors = ::score::crypto::daemon::common::actors;
namespace cm_ops = ::score::crypto::daemon::cert_management::operations;

namespace
{

score::Result<proto::ControlRequest> MakeControlRequest(proto::OperationRequestBuilder builder,
                                                        proto::DataNodeId context_id)
{
    auto operation_result = builder.build();
    if (!operation_result.has_value())
    {
        return score::Result<proto::ControlRequest>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build operation request")};
    }

    proto::ControlRequest request{};
    request.operation = operation_result.value();
    request.data_node_id = context_id;
    return request;
}

// Public error code the daemon reported for a failed operation; fallback when the response carries none.
CryptoErrorCode GetResponseError(const proto::ControlResponseValidator& validator,
                                 const CryptoErrorCode fallback = CryptoErrorCode::kOperationFailed) noexcept
{
    return validator.getOperationError().value_or(fallback);
}

/// Sends a trust-store request and maps any failure to the error the daemon reported.
score::Result<std::monostate> SendTrustStoreRequest(score::crypto::api::control_plane::IConnection& connection,
                                                    const proto::ControlRequest& request,
                                                    const proto::OperationIdentifier& op_id)
{
    auto resp = connection.SendRequest(request);
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
    {
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(GetResponseError(validator), validator.getError())};
    }
    return std::monostate{};
}

}  // namespace

// ===========================================================================
// ContextReleaseCallbackImpl: sends CTX_CLOSE when the last reference is dropped
// ===========================================================================

class TrustStoreManagementContextImpl::ContextReleaseCallbackImpl final : public IReleaseCallback
{
  public:
    ContextReleaseCallbackImpl(std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
                               proto::DataNodeId context_id)
        : m_connection(std::move(connection)), m_context_id(context_id)
    {
    }

    ContextReleaseCallbackImpl(const ContextReleaseCallbackImpl&) = delete;
    ContextReleaseCallbackImpl& operator=(const ContextReleaseCallbackImpl&) = delete;
    ContextReleaseCallbackImpl(ContextReleaseCallbackImpl&&) = delete;
    ContextReleaseCallbackImpl& operator=(ContextReleaseCallbackImpl&&) = delete;

    ~ContextReleaseCallbackImpl() override
    {
        if (!m_connection)
        {
            score::mw::log::LogError() << "[API][TrustStoreMgmtCtxImpl] ERROR: Connection not initialized during "
                                          "CTX_CLOSE";
            return;
        }
        auto req = proto::ControlRequestBuilder()
                       .forDataNodeId(m_context_id)
                       .operation(score::crypto::daemon::mediator::operations::CloseContext())
                       .build();
        if (!req.has_value())
        {
            score::mw::log::LogError() << "[API][TrustStoreMgmtCtxImpl] ERROR: Failed to build CTX_CLOSE request";
            return;
        }
        auto resp = m_connection->SendRequest(req.value());
        auto validator = proto::ControlResponseValidator::FromResult(resp);
        validator.expectOperation(score::crypto::daemon::mediator::operations::CloseContext()).expectSuccess();
        if (!validator.isValid())
        {
            score::mw::log::LogError() << "[API][TrustStoreMgmtCtxImpl] ERROR: CTX_CLOSE failed: "
                                       << validator.getError();
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

// ===========================================================================
// Construction and destruction
// ===========================================================================

TrustStoreManagementContextImpl::TrustStoreManagementContextImpl(
    std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
    uint64_t context_id,
    std::shared_ptr<IBufferTranscoder> transcoder)
    : m_connection(std::move(connection)),
      m_context_id(context_id),
      m_transcoder(std::move(transcoder)),
      m_context_release_callback(std::make_shared<ContextReleaseCallbackImpl>(m_connection, m_context_id))
{
}

TrustStoreManagementContextImpl::~TrustStoreManagementContextImpl() = default;

// ===========================================================================
// Membership
// ===========================================================================

score::Result<std::monostate> TrustStoreManagementContextImpl::AddCertificateToTrustStore(
    const CryptoResourceId& trust_store,
    const CryptoResourceId& cert)
{
    // Request: [0]=trust-store node id (uint64), [1]=certificate or slot node id (uint64)
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_MANAGEMENT, cm_ops::TRUST_STORE_ADD_CERT};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint64(trust_store.id)
                   .with_in_val_uint64(cert.id)
                   .build();
    if (!req.has_value())
    {
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build TRUST_STORE_ADD_CERT")};
    }
    return SendTrustStoreRequest(*m_connection, req.value(), op_id);
}

score::Result<std::monostate> TrustStoreManagementContextImpl::AddCertificateToTrustStoreWithCrl(
    const CryptoResourceId& trust_store,
    const CryptoResourceId& cert)
{
    // Request: [0]=trust-store node id (uint64), [1]=certificate or slot node id (uint64),
    //          [2]=with_crl (uint8, non-zero requests the daemon-side CRL association)
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_MANAGEMENT, cm_ops::TRUST_STORE_ADD_CERT};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint64(trust_store.id)
                   .with_in_val_uint64(cert.id)
                   .with_in_val_uint8(1U)
                   .build();
    if (!req.has_value())
    {
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build TRUST_STORE_ADD_CERT")};
    }
    return SendTrustStoreRequest(*m_connection, req.value(), op_id);
}

score::Result<std::monostate> TrustStoreManagementContextImpl::RemoveCertificateFromTrustStore(
    const CryptoResourceId& trust_store,
    const CryptoResourceId& cert)
{
    // Request: [0]=trust-store node id (uint64), [1]=certificate node id (uint64).
    // The daemon resolves the fingerprint from the loaded certificate.
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_MANAGEMENT, cm_ops::TRUST_STORE_REMOVE_CERT_BY_ID};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint64(trust_store.id)
                   .with_in_val_uint64(cert.id)
                   .build();
    if (!req.has_value())
    {
        return score::Result<std::monostate>{
            score::unexpect,
            MakeError(CryptoErrorCode::kOperationFailed, "Failed to build TRUST_STORE_REMOVE_CERT_BY_ID")};
    }
    return SendTrustStoreRequest(*m_connection, req.value(), op_id);
}

score::Result<std::monostate> TrustStoreManagementContextImpl::RemoveCertificateFromTrustStore(
    const CryptoResourceId& trust_store,
    score::cpp::span<const uint8_t, kSha256FingerprintSize> sha256_fingerprint)
{
    // Request: [0]=trust-store node id (uint64), [1]=SHA-256 fingerprint (data buffer)
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_MANAGEMENT, cm_ops::TRUST_STORE_REMOVE_CERT};
    proto::OperationRequestBuilder builder;
    builder.operation(op_id).with_in_val_uint64(trust_store.id);
    auto tspan_result = m_transcoder->Acquire(sha256_fingerprint);
    if (!tspan_result.has_value())
    {
        return score::Result<std::monostate>{score::unexpect, tspan_result.error()};
    }
    TranscoderSpan tspan = std::move(tspan_result.value());
    m_transcoder->AppendInputBuffer(builder, tspan);

    auto request_result = MakeControlRequest(std::move(builder), m_context_id);
    if (!request_result.has_value())
    {
        return score::Result<std::monostate>{score::unexpect, request_result.error()};
    }
    return SendTrustStoreRequest(*m_connection, request_result.value(), op_id);
}

// ===========================================================================
// Member state
// ===========================================================================

score::Result<std::monostate> TrustStoreManagementContextImpl::EnableTrustStoreMember(
    const CryptoResourceId& trust_store,
    const CryptoResourceId& slot)
{
    // Request: [0]=trust-store node id (uint64), [1]=member slot node id (uint64)
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_MANAGEMENT, cm_ops::TRUST_STORE_ENABLE_CERT};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint64(trust_store.id)
                   .with_in_val_uint64(slot.id)
                   .build();
    if (!req.has_value())
    {
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build TRUST_STORE_ENABLE_CERT")};
    }
    return SendTrustStoreRequest(*m_connection, req.value(), op_id);
}

score::Result<std::monostate> TrustStoreManagementContextImpl::DisableTrustStoreMember(
    const CryptoResourceId& trust_store,
    const CryptoResourceId& slot)
{
    // Request: [0]=trust-store node id (uint64), [1]=member slot node id (uint64)
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_MANAGEMENT, cm_ops::TRUST_STORE_DISABLE_CERT};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint64(trust_store.id)
                   .with_in_val_uint64(slot.id)
                   .build();
    if (!req.has_value())
    {
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build TRUST_STORE_DISABLE_CERT")};
    }
    return SendTrustStoreRequest(*m_connection, req.value(), op_id);
}

score::Result<std::monostate> TrustStoreManagementContextImpl::AcknowledgeTrustStoreMemberUpdate(
    const CryptoResourceId& trust_store,
    const CryptoResourceId& slot,
    score::cpp::span<const uint8_t, kSha256FingerprintSize> expected_sha256_fingerprint)
{
    // Request: [0]=trust-store node id (uint64), [1]=member slot node id (uint64),
    //          [2]=expected SHA-256 fingerprint (data buffer)
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_MANAGEMENT, cm_ops::TRUST_STORE_ACK_UPDATE};
    proto::OperationRequestBuilder builder;
    builder.operation(op_id).with_in_val_uint64(trust_store.id).with_in_val_uint64(slot.id);
    auto tspan_result = m_transcoder->Acquire(expected_sha256_fingerprint);
    if (!tspan_result.has_value())
    {
        return score::Result<std::monostate>{score::unexpect, tspan_result.error()};
    }
    TranscoderSpan tspan = std::move(tspan_result.value());
    m_transcoder->AppendInputBuffer(builder, tspan);

    auto request_result = MakeControlRequest(std::move(builder), m_context_id);
    if (!request_result.has_value())
    {
        return score::Result<std::monostate>{score::unexpect, request_result.error()};
    }
    return SendTrustStoreRequest(*m_connection, request_result.value(), op_id);
}

// ===========================================================================
// CRL management for exclusive members
// ===========================================================================

score::Result<std::monostate> TrustStoreManagementContextImpl::ImportCrlForTrustStoreMember(
    const CryptoResourceId& trust_store,
    const CryptoResourceId& slot,
    score::cpp::span<const uint8_t> crl_data,
    FormatType format)
{
    // Request: [0]=trust-store node id (uint64), [1]=member slot node id (uint64),
    //          [2]=CRL format (uint8), [3]=CRL bytes (data buffer)
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_MANAGEMENT, cm_ops::TRUST_STORE_IMPORT_CRL_FOR_MEMBER};
    proto::OperationRequestBuilder builder;
    builder.operation(op_id)
        .with_in_val_uint64(trust_store.id)
        .with_in_val_uint64(slot.id)
        .with_in_val_uint8(static_cast<std::uint8_t>(format));
    auto tspan_result = m_transcoder->Acquire(crl_data);
    if (!tspan_result.has_value())
    {
        return score::Result<std::monostate>{score::unexpect, tspan_result.error()};
    }
    TranscoderSpan tspan = std::move(tspan_result.value());
    m_transcoder->AppendInputBuffer(builder, tspan);

    auto request_result = MakeControlRequest(std::move(builder), m_context_id);
    if (!request_result.has_value())
    {
        return score::Result<std::monostate>{score::unexpect, request_result.error()};
    }
    return SendTrustStoreRequest(*m_connection, request_result.value(), op_id);
}

score::Result<std::monostate> TrustStoreManagementContextImpl::DeleteCrlForTrustStoreMember(
    const CryptoResourceId& trust_store,
    const CryptoResourceId& slot)
{
    // Request: [0]=trust-store node id (uint64), [1]=member slot node id (uint64)
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_MANAGEMENT, cm_ops::TRUST_STORE_DELETE_CRL_FOR_MEMBER};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint64(trust_store.id)
                   .with_in_val_uint64(slot.id)
                   .build();
    if (!req.has_value())
    {
        return score::Result<std::monostate>{
            score::unexpect,
            MakeError(CryptoErrorCode::kOperationFailed, "Failed to build TRUST_STORE_DELETE_CRL_FOR_MEMBER")};
    }
    return SendTrustStoreRequest(*m_connection, req.value(), op_id);
}

}  // namespace crypto

}  // namespace score

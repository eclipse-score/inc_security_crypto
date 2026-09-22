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
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"
#include "score/crypto/src/daemon/provider/cert_management/cert_management_operations.hpp"

#include "score/mw/log/logging.h"
#include "score/result/result.h"

#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

namespace score
{

namespace crypto
{

namespace proto = ::score::crypto::daemon::control_plane::protocol;
namespace actors = ::score::crypto::daemon::common::actors;
namespace cm_ops = ::score::crypto::daemon::provider::cert_management;

// ===========================================================================
// ContextReleaseCallbackImpl — sends CTX_CLOSE on last reference drop
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
// Construction / destruction
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

score::Result<proto::ControlRequest> TrustStoreManagementContextImpl::MakeControlRequest(
    proto::OperationRequestBuilder builder,
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

// ===========================================================================
// Trust store mutations
// ===========================================================================

score::Result<std::monostate> TrustStoreManagementContextImpl::AddCertificateToTrustStore(
    const CryptoResourceId& trust_store,
    const CryptoResourceId& cert)
{
    // Request: [0]=ts_node_id (uint64), [1]=cert_node_id (uint64)
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_MANAGEMENT, cm_ops::TRUST_STORE_ADD_CERT};
    auto builder = proto::ControlRequestBuilder()
                       .forDataNodeId(m_context_id)
                       .operation(op_id)
                       .with_in_val_uint64(trust_store.id)
                       .with_in_val_uint64(cert.id);
    auto req = std::move(builder).build();
    if (!req.has_value())
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build TRUST_STORE_ADD_CERT")};
    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    return std::monostate{};
}

score::Result<std::monostate> TrustStoreManagementContextImpl::AddCertificateToTrustStoreWithCrl(
    const CryptoResourceId& trust_store,
    const CryptoResourceId& cert)
{
    // Request: [0]=ts_node_id (uint64), [1]=cert_node_id (uint64), [2]=with_crl (uint8)
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_MANAGEMENT, cm_ops::TRUST_STORE_ADD_CERT};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint64(trust_store.id)
                   .with_in_val_uint64(cert.id)
                   .with_in_val_uint8(1U)
                   .build();
    if (!req.has_value())
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build TRUST_STORE_ADD_CERT")};
    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    return std::monostate{};
}

score::Result<std::monostate> TrustStoreManagementContextImpl::RemoveCertificateFromTrustStore(
    const CryptoResourceId& trust_store,
    const CryptoResourceId& cert)
{
    // Daemon-side fingerprint resolution: TRUST_STORE_REMOVE_CERT_BY_ID (0xC5)
    // Request: [0]=ts_node_id (uint64), [1]=cert_node_id (uint64)
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_MANAGEMENT, cm_ops::TRUST_STORE_REMOVE_CERT_BY_ID};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint64(trust_store.id)
                   .with_in_val_uint64(cert.id)
                   .build();
    if (!req.has_value())
        return score::Result<std::monostate>{
            score::unexpect,
            MakeError(CryptoErrorCode::kOperationFailed, "Failed to build TRUST_STORE_REMOVE_CERT_BY_ID")};
    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    return std::monostate{};
}

score::Result<std::monostate> TrustStoreManagementContextImpl::RemoveCertificateFromTrustStore(
    const CryptoResourceId& trust_store,
    score::cpp::span<const uint8_t> sha256_fingerprint)
{
    // Direct fingerprint-based removal: TRUST_STORE_REMOVE_CERT (0xC1)
    // Request: [0]=ts_node_id (uint64), [1]=fingerprint bytes (data buffer)
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_MANAGEMENT, cm_ops::TRUST_STORE_REMOVE_CERT};
    proto::OperationRequestBuilder builder;
    builder.operation(op_id).with_in_val_uint64(trust_store.id);
    auto tspan_result = m_transcoder->Acquire(sha256_fingerprint);
    if (!tspan_result.has_value())
        return score::Result<std::monostate>{score::unexpect, tspan_result.error()};
    TranscoderSpan tspan = std::move(tspan_result.value());
    m_transcoder->AppendInputBuffer(builder, tspan);
    auto request_result = TrustStoreManagementContextImpl::MakeControlRequest(std::move(builder), m_context_id);
    if (!request_result.has_value())
        return score::Result<std::monostate>{score::unexpect, request_result.error()};
    auto resp = m_connection->SendRequest(request_result.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    return std::monostate{};
}

score::Result<std::monostate> TrustStoreManagementContextImpl::EnableTrustStoreMember(
    const CryptoResourceId& trust_store,
    const CryptoResourceId& slot)
{
    // Request: [0]=ts_node_id (uint64), [1]=slot_node_id (uint64)
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_MANAGEMENT, cm_ops::TRUST_STORE_ENABLE_CERT};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint64(trust_store.id)
                   .with_in_val_uint64(slot.id)
                   .build();
    if (!req.has_value())
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build TRUST_STORE_ENABLE_CERT")};
    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    return std::monostate{};
}

score::Result<std::monostate> TrustStoreManagementContextImpl::DisableTrustStoreMember(
    const CryptoResourceId& trust_store,
    const CryptoResourceId& slot)
{
    // Request: [0]=ts_node_id (uint64), [1]=slot_node_id (uint64)
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_MANAGEMENT, cm_ops::TRUST_STORE_DISABLE_CERT};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint64(trust_store.id)
                   .with_in_val_uint64(slot.id)
                   .build();
    if (!req.has_value())
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build TRUST_STORE_DISABLE_CERT")};
    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    return std::monostate{};
}

score::Result<std::monostate> TrustStoreManagementContextImpl::AcknowledgeTrustStoreMemberUpdate(
    const CryptoResourceId& trust_store,
    const CryptoResourceId& slot)
{
    // Request: [0]=ts_node_id (uint64), [1]=slot_node_id (uint64)
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_MANAGEMENT, cm_ops::TRUST_STORE_ACK_UPDATE};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint64(trust_store.id)
                   .with_in_val_uint64(slot.id)
                   .build();
    if (!req.has_value())
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build TRUST_STORE_ACK_UPDATE")};
    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    return std::monostate{};
}

score::Result<std::monostate> TrustStoreManagementContextImpl::ImportCrlForTrustStoreMember(
    const CryptoResourceId& trust_store,
    const CryptoResourceId& slot,
    score::cpp::span<const uint8_t> crl_data,
    FormatType format)
{
    // Request: [0]=ts_node_id (uint64), [1]=slot_node_id (uint64),
    //          [2]=format (uint8), [3]=CRL bytes (data buffer)
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_MANAGEMENT, cm_ops::TRUST_STORE_IMPORT_CRL_FOR_MEMBER};
    proto::OperationRequestBuilder builder;
    builder.operation(op_id)
        .with_in_val_uint64(trust_store.id)
        .with_in_val_uint64(slot.id)
        .with_in_val_uint8(static_cast<std::uint8_t>(format));
    auto tspan_result = m_transcoder->Acquire(crl_data);
    if (!tspan_result.has_value())
        return score::Result<std::monostate>{score::unexpect, tspan_result.error()};
    TranscoderSpan tspan = std::move(tspan_result.value());
    m_transcoder->AppendInputBuffer(builder, tspan);
    auto request_result = TrustStoreManagementContextImpl::MakeControlRequest(std::move(builder), m_context_id);
    if (!request_result.has_value())
        return score::Result<std::monostate>{score::unexpect, request_result.error()};
    auto resp = m_connection->SendRequest(request_result.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    return std::monostate{};
}

score::Result<std::monostate> TrustStoreManagementContextImpl::DeleteCrlForTrustStoreMember(
    const CryptoResourceId& trust_store,
    const CryptoResourceId& slot)
{
    // Request: [0]=ts_node_id (uint64), [1]=slot_node_id (uint64)
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_MANAGEMENT, cm_ops::TRUST_STORE_DELETE_CRL_FOR_MEMBER};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint64(trust_store.id)
                   .with_in_val_uint64(slot.id)
                   .build();
    if (!req.has_value())
        return score::Result<std::monostate>{
            score::unexpect,
            MakeError(CryptoErrorCode::kOperationFailed, "Failed to build TRUST_STORE_DELETE_CRL_FOR_MEMBER")};
    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    return std::monostate{};
}

}  // namespace crypto

}  // namespace score

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

#include "score/crypto/src/api/contexts/src/cert_verification_context_impl.hpp"

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/common/src/i_release_callback.hpp"
#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/cert_verification_operations.hpp"

#include "score/mw/log/logging.h"
#include "score/result/result.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <utility>

namespace score
{

namespace crypto
{

namespace proto = ::score::crypto::daemon::control_plane::protocol;
namespace actors = ::score::crypto::daemon::common::actors;
namespace cv_ops = ::score::crypto::daemon::provider::cert_verification;

// ---------------------------------------------------------------------------
// ContextReleaseCallbackImpl — sends CTX_CLOSE on last reference drop
// ---------------------------------------------------------------------------

class CertVerificationContextImpl::ContextReleaseCallbackImpl final : public IReleaseCallback
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
            score::mw::log::LogError() << "[API][CertVerifyCtxImpl] ERROR: Connection not initialized during CTX_CLOSE";
            return;
        }
        auto req = proto::ControlRequestBuilder()
                       .forDataNodeId(m_context_id)
                       .operation(score::crypto::daemon::mediator::operations::CloseContext())
                       .build();
        if (!req.has_value())
        {
            score::mw::log::LogError() << "[API][CertVerifyCtxImpl] ERROR: Failed to build CTX_CLOSE request";
            return;
        }
        auto resp = m_connection->SendRequest(req.value());
        auto validator = proto::ControlResponseValidator::FromResult(resp);
        validator.expectOperation(score::crypto::daemon::mediator::operations::CloseContext()).expectSuccess();
        if (!validator.isValid())
        {
            score::mw::log::LogError() << "[API][CertVerifyCtxImpl] ERROR: CTX_CLOSE failed: " << validator.getError();
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
// Construction / destruction
// ---------------------------------------------------------------------------

CertVerificationContextImpl::CertVerificationContextImpl(
    std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
    uint64_t context_id)
    : m_connection(std::move(connection)),
      m_context_id(context_id),
      m_context_release_callback(std::make_shared<ContextReleaseCallbackImpl>(m_connection, m_context_id))
{
}

CertVerificationContextImpl::~CertVerificationContextImpl() = default;

// ---------------------------------------------------------------------------
// Internal helper — send a no-parameter opcode, validate success
// ---------------------------------------------------------------------------

score::Result<std::monostate> CertVerificationContextImpl::SendSimpleOp(const proto::OperationIdentifier& op_id) const
{
    auto req = proto::ControlRequestBuilder().forDataNodeId(m_context_id).operation(op_id).build();
    if (!req.has_value())
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, "Failed to build request")};
    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    return std::monostate{};
}

// ---------------------------------------------------------------------------
// Setters
// ---------------------------------------------------------------------------

score::Result<std::monostate> CertVerificationContextImpl::SetCertificate(const CryptoResourceId& cert)
{
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_VERIFICATION, cv_ops::CERT_VERIFY_SET_LEAF};
    auto req =
        proto::ControlRequestBuilder().forDataNodeId(m_context_id).operation(op_id).with_in_val_uint64(cert.id).build();
    if (!req.has_value())
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, "Failed to build SET_LEAF")};
    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    return std::monostate{};
}

score::Result<std::monostate> CertVerificationContextImpl::SetCertificateChain(
    score::cpp::span<const CryptoResourceId> chain)
{
    // Build all cert IDs into a single IPC request (daemon executor reads ALL params for SET_CHAIN).
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_VERIFICATION, cv_ops::CERT_VERIFY_SET_CHAIN};
    proto::ControlRequestBuilder builder{};
    builder.forDataNodeId(m_context_id).operation(op_id);
    for (const auto& cert : chain)
        builder.with_in_val_uint64(cert.id);
    auto req = builder.build();
    if (!req.has_value())
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, "Failed to build SET_CHAIN")};
    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    return std::monostate{};
}

score::Result<std::monostate> CertVerificationContextImpl::SetVerificationTrustStore(
    const CryptoResourceId& trust_store)
{
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_VERIFICATION, cv_ops::CERT_VERIFY_SET_TRUST_STORE};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint64(trust_store.id)
                   .build();
    if (!req.has_value())
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build SET_TRUST_STORE")};
    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    return std::monostate{};
}

score::Result<std::monostate> CertVerificationContextImpl::SetTrustedCertificates(
    score::cpp::span<const CryptoResourceId> certs)
{
    // Send the complete trusted-certificate set in one IPC request.
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_VERIFICATION, cv_ops::CERT_VERIFY_SET_TRUSTED};
    proto::ControlRequestBuilder builder{};
    builder.forDataNodeId(m_context_id).operation(op_id);
    for (const auto& cert : certs)
        builder.with_in_val_uint64(cert.id);

    auto req = builder.build();
    if (!req.has_value())
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build SET_TRUSTED")};

    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    return std::monostate{};
}

score::Result<std::monostate> CertVerificationContextImpl::SetChainTerminationPolicy(ChainTerminationPolicy policy)
{
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_VERIFICATION, cv_ops::CERT_VERIFY_SET_POLICY};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint8(static_cast<std::uint8_t>(policy))
                   .build();
    if (!req.has_value())
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build SET_POLICY")};
    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    return std::monostate{};
}

score::Result<std::monostate> CertVerificationContextImpl::SetAdditionalCertificates(
    score::cpp::span<const CryptoResourceId> certificates)
{
    // All IDs in a single request (daemon executor reads ALL params for SET_ADDITIONAL).
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_VERIFICATION, cv_ops::CERT_VERIFY_SET_ADDITIONAL};
    proto::ControlRequestBuilder builder{};
    builder.forDataNodeId(m_context_id).operation(op_id);
    for (const auto& cert : certificates)
        builder.with_in_val_uint64(cert.id);
    auto req = builder.build();
    if (!req.has_value())
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build SET_ADDITIONAL")};
    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    return std::monostate{};
}

score::Result<std::monostate> CertVerificationContextImpl::SetVerificationTime(int64_t epoch_seconds)
{
    // int64 is sent as the raw bit-pattern of a uint64 — no signed int wire variant exists.
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_VERIFICATION,
                                           cv_ops::CERT_VERIFY_SET_VERIFICATION_TIME};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint64(static_cast<std::uint64_t>(epoch_seconds))
                   .build();
    if (!req.has_value())
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build SET_VERIFICATION_TIME")};
    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    return std::monostate{};
}

score::Result<std::monostate> CertVerificationContextImpl::SetRevocationCheckPolicy(RevocationCheckPolicy policy)
{
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_VERIFICATION,
                                           cv_ops::CERT_VERIFY_SET_REVOCATION_POLICY};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint8(static_cast<std::uint8_t>(policy))
                   .build();
    if (!req.has_value())
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build SET_REVOCATION_POLICY")};
    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    return std::monostate{};
}

score::Result<std::monostate> CertVerificationContextImpl::SetEvidenceMode(VerificationEvidenceMode mode)
{
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_VERIFICATION, cv_ops::CERT_VERIFY_SET_EVIDENCE_MODE};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint8(static_cast<std::uint8_t>(mode))
                   .build();
    if (!req.has_value())
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build SET_EVIDENCE_MODE")};
    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    return std::monostate{};
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

score::Result<CertVerifyResult> CertVerificationContextImpl::Verify()
{
    m_verify_result.reset();
    m_chain_count = 0U;

    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_VERIFICATION, cv_ops::CERT_VERIFY};
    auto req = proto::ControlRequestBuilder().forDataNodeId(m_context_id).operation(op_id).build();
    if (!req.has_value())
        return score::Result<CertVerifyResult>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build CERT_VERIFY request")};

    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<CertVerifyResult>{score::unexpect,
                                               MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};

    // param[0][0] = uint8 CertVerifyResult, param[0][1] = uint32 certificate count
    auto result_res = validator.getParameterAt<std::uint8_t>(0, 0);
    if (!result_res.has_value())
        return score::Result<CertVerifyResult>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "CERT_VERIFY response missing result code")};

    auto count_res = validator.getParameterAt<std::uint32_t>(0, 1);
    if (!count_res.has_value())
        return score::Result<CertVerifyResult>{
            score::unexpect,
            MakeError(CryptoErrorCode::kOperationFailed, "CERT_VERIFY response missing certificate count")};

    const auto verify_result = static_cast<CertVerifyResult>(result_res.value());
    m_verify_result = verify_result;
    m_chain_count = count_res.value();

    return verify_result;
}

score::Result<std::size_t> CertVerificationContextImpl::GetVerifiedChainCertificateCount() const
{
    if (!m_verify_result.has_value())
        return score::Result<std::size_t>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Verify() has not been called successfully")};
    return static_cast<std::size_t>(m_chain_count);
}

score::Result<std::size_t> CertVerificationContextImpl::GetVerifiedChainExportSize(FormatType format) const
{
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_VERIFICATION,
                                           cv_ops::CERT_GET_VERIFIED_CHAIN_EXPORT_SIZE};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint8(static_cast<std::uint8_t>(format))
                   .build();
    if (!req.has_value())
        return score::Result<std::size_t>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build chain export size request")};
    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::size_t>{score::unexpect,
                                          MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    auto size = validator.getParameterAt<std::uint64_t>(0, 0);
    if (!size.has_value())
        return score::Result<std::size_t>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Chain export size response missing size")};
    return static_cast<std::size_t>(size.value());
}

score::Result<std::size_t> CertVerificationContextImpl::ExportVerifiedChain(FormatType format,
                                                                            score::cpp::span<uint8_t> out) const
{
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_VERIFICATION, cv_ops::CERT_EXPORT_VERIFIED_CHAIN};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint8(static_cast<std::uint8_t>(format))
                   .build();
    if (!req.has_value())
        return score::Result<std::size_t>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build chain export request")};
    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::size_t>{score::unexpect,
                                          MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    auto count = validator.getParameterAt<std::uint64_t>(0, 0);
    auto bytes = validator.getParameterAt<daemon::common::OwnedBuffer>(0, 1);
    if (!count.has_value())
        return score::Result<std::size_t>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Chain export response missing count")};
    if (!bytes.has_value())
        return score::Result<std::size_t>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Chain export response missing bytes")};
    if (out.empty())
        return score::Result<std::size_t>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Chain export output span is empty")};
    if (out.size() < bytes.value().size())
        return score::Result<std::size_t>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Chain export output span too small")};
    std::copy(bytes.value().begin(), bytes.value().end(), out.data());
    return bytes.value().size();
}

score::Result<std::size_t> CertVerificationContextImpl::GetVerifiedCertificateExportSize(std::size_t index,
                                                                                         FormatType format) const
{
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_VERIFICATION,
                                           cv_ops::CERT_GET_VERIFIED_CERT_EXPORT_SIZE};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint64(static_cast<std::uint64_t>(index))
                   .with_in_val_uint8(static_cast<std::uint8_t>(format))
                   .build();
    if (!req.has_value())
        return score::Result<std::size_t>{
            score::unexpect,
            MakeError(CryptoErrorCode::kOperationFailed, "Failed to build certificate export size request")};
    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::size_t>{score::unexpect,
                                          MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    auto size = validator.getParameterAt<std::uint64_t>(0, 0);
    if (!size.has_value())
        return score::Result<std::size_t>{
            score::unexpect,
            MakeError(CryptoErrorCode::kOperationFailed, "Certificate export size response missing size")};
    return static_cast<std::size_t>(size.value());
}

score::Result<std::size_t> CertVerificationContextImpl::ExportVerifiedCertificate(std::size_t index,
                                                                                  FormatType format,
                                                                                  score::cpp::span<uint8_t> out) const
{
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_VERIFICATION, cv_ops::CERT_EXPORT_VERIFIED_CERT};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint64(static_cast<std::uint64_t>(index))
                   .with_in_val_uint8(static_cast<std::uint8_t>(format))
                   .build();
    if (!req.has_value())
        return score::Result<std::size_t>{
            score::unexpect,
            MakeError(CryptoErrorCode::kOperationFailed, "Failed to build certificate export request")};
    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::size_t>{score::unexpect,
                                          MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    auto bytes = validator.getParameterAt<daemon::common::OwnedBuffer>(0, 0);
    if (!bytes.has_value())
        return score::Result<std::size_t>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Certificate export response missing bytes")};
    if (out.empty())
        return score::Result<std::size_t>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Certificate export output span is empty")};
    if (out.size() < bytes.value().size())
        return score::Result<std::size_t>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Certificate export output span too small")};
    std::copy(bytes.value().begin(), bytes.value().end(), out.data());
    return bytes.value().size();
}

score::Result<std::size_t> CertVerificationContextImpl::GetSelectedCrlMetadataCount() const
{
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_VERIFICATION, cv_ops::CERT_GET_SELECTED_CRL_METADATA};
    auto req = proto::ControlRequestBuilder().forDataNodeId(m_context_id).operation(op_id).build();
    if (!req.has_value())
        return score::Result<std::size_t>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build GET_SELECTED_CRL_METADATA")};
    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::size_t>{score::unexpect,
                                          MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    auto count = validator.getParameterAt<std::uint64_t>(0, 0);
    if (!count.has_value())
        return score::Result<std::size_t>{
            score::unexpect,
            MakeError(CryptoErrorCode::kOperationFailed, "Selected CRL metadata count response missing count")};
    return static_cast<std::size_t>(count.value());
}

score::Result<std::size_t> CertVerificationContextImpl::GetSelectedCrlMetadata(score::cpp::span<CrlMetadata> out) const
{
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_VERIFICATION, cv_ops::CERT_GET_SELECTED_CRL_METADATA};
    auto req = proto::ControlRequestBuilder().forDataNodeId(m_context_id).operation(op_id).build();
    if (!req.has_value())
        return score::Result<std::size_t>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build GET_SELECTED_CRL_METADATA")};
    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::size_t>{score::unexpect,
                                          MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    auto count = validator.getParameterAt<std::uint64_t>(0, 0);
    auto bytes = validator.getParameterAt<daemon::common::OwnedBuffer>(0, 1);
    if (!count.has_value())
        return score::Result<std::size_t>{
            score::unexpect,
            MakeError(CryptoErrorCode::kOperationFailed, "Selected CRL metadata response missing count")};
    if (!bytes.has_value())
        return score::Result<std::size_t>{
            score::unexpect,
            MakeError(CryptoErrorCode::kOperationFailed, "Selected CRL metadata response missing bytes")};
    const auto entry_count = static_cast<std::size_t>(count.value());
    if (bytes.value().size() != entry_count * CrlMetadataWireLayout::kEntrySize)
        return score::Result<std::size_t>{
            score::unexpect,
            MakeError(CryptoErrorCode::kOperationFailed, "Selected CRL metadata buffer size is invalid")};
    if (out.empty())
        return score::Result<std::size_t>{
            score::unexpect,
            MakeError(CryptoErrorCode::kOperationFailed, "Selected CRL metadata output span is empty")};
    if (out.size() < entry_count)
        return score::Result<std::size_t>{
            score::unexpect,
            MakeError(CryptoErrorCode::kOperationFailed, "Selected CRL metadata output span too small")};
    for (std::size_t i = 0U; i < entry_count; ++i)
    {
        const auto* entry = bytes.value().data() + i * CrlMetadataWireLayout::kEntrySize;
        std::memcpy(out[i].fingerprint.data(),
                    entry + CrlMetadataWireLayout::kCrlFingerprintOffset,
                    CrlMetadataWireLayout::kFingerprintSize);
        std::memcpy(out[i].issuer_fingerprint.data(),
                    entry + CrlMetadataWireLayout::kIssuerFingerprintOffset,
                    CrlMetadataWireLayout::kFingerprintSize);
        std::memcpy(&out[i].this_update, entry + CrlMetadataWireLayout::kThisUpdateOffset, sizeof(out[i].this_update));
        std::memcpy(&out[i].next_update, entry + CrlMetadataWireLayout::kNextUpdateOffset, sizeof(out[i].next_update));
        std::memcpy(&out[i].crl_number, entry + CrlMetadataWireLayout::kCrlNumberOffset, sizeof(out[i].crl_number));
    }
    return entry_count;
}

}  // namespace crypto

}  // namespace score

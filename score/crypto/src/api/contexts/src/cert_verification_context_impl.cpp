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
#include "score/crypto/src/daemon/cert_management/interfaces/cert_verification_operations.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/crl_metadata_wire_layout.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"

#include "score/mw/log/logging.h"
#include "score/result/result.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

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

/// Failure for a request that could not be assembled on the client. No daemon verdict exists in this case.
score::Result<std::monostate> BuildRequestFailure(std::string_view message)
{
    return score::Result<std::monostate>{score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, message)};
}

/// Sends a request and requires a successful reply to @p op_id. A failure carries the error the daemon reported.
score::Result<std::monostate> SendVerificationRequest(score::crypto::api::control_plane::IConnection& connection,
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
// Construction and destruction
// ===========================================================================

CertVerificationContextImpl::CertVerificationContextImpl(
    std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
    uint64_t context_id,
    std::shared_ptr<IBufferTranscoder> transcoder)
    : m_connection(std::move(connection)), m_context_id(context_id), m_transcoder(std::move(transcoder))
{
}

CertVerificationContextImpl::~CertVerificationContextImpl()
{
    CloseContext();
}

void CertVerificationContextImpl::CloseContext() noexcept
{
    if (!m_connection)
    {
        score::mw::log::LogError() << "[API][CertVerificationCtx] ERROR: Connection not initialized during CTX_CLOSE";
        return;
    }
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(score::crypto::daemon::mediator::operations::CloseContext())
                   .build();
    if (!req.has_value())
    {
        score::mw::log::LogError() << "[API][CertVerificationCtx] ERROR: Failed to build CTX_CLOSE request";
        return;
    }
    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(score::crypto::daemon::mediator::operations::CloseContext()).expectSuccess();
    if (!validator.isValid())
    {
        score::mw::log::LogError() << "[API][CertVerificationCtx] ERROR: CTX_CLOSE failed: " << validator.getError();
    }
}

// ===========================================================================
// Configuration setters
// ===========================================================================

score::Result<std::monostate> CertVerificationContextImpl::SetCertificate(const CryptoResourceId& cert)
{
    // Request: [0] = certificate node id (uint64).
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_VERIFICATION, cm_ops::CERT_VERIFY_SET_LEAF};
    auto req =
        proto::ControlRequestBuilder().forDataNodeId(m_context_id).operation(op_id).with_in_val_uint64(cert.id).build();
    if (!req.has_value())
    {
        return BuildRequestFailure("Failed to build CERT_VERIFY_SET_LEAF");
    }
    return SendVerificationRequest(*m_connection, req.value(), op_id);
}

score::Result<std::monostate> CertVerificationContextImpl::SetCertificateChain(
    score::cpp::span<const CryptoResourceId> chain)
{
    // Request: one certificate node id (uint64) per entry, leaf first. The daemon reads every parameter.
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_VERIFICATION, cm_ops::CERT_VERIFY_SET_CHAIN};
    proto::ControlRequestBuilder builder{};
    builder.forDataNodeId(m_context_id).operation(op_id);
    for (const auto& cert : chain)
    {
        builder.with_in_val_uint64(cert.id);
    }
    auto req = builder.build();
    if (!req.has_value())
    {
        return BuildRequestFailure("Failed to build CERT_VERIFY_SET_CHAIN");
    }
    return SendVerificationRequest(*m_connection, req.value(), op_id);
}

score::Result<std::monostate> CertVerificationContextImpl::SetVerificationTrustStore(
    const CryptoResourceId& trust_store)
{
    // Request: [0] = trust-store node id (uint64).
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_VERIFICATION, cm_ops::CERT_VERIFY_SET_TRUST_STORE};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint64(trust_store.id)
                   .build();
    if (!req.has_value())
    {
        return BuildRequestFailure("Failed to build CERT_VERIFY_SET_TRUST_STORE");
    }
    return SendVerificationRequest(*m_connection, req.value(), op_id);
}

score::Result<std::monostate> CertVerificationContextImpl::SetTrustedCertificates(
    score::cpp::span<const CryptoResourceId> certs)
{
    // Request: one certificate node id (uint64) per entry. The complete set travels in one request.
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_VERIFICATION, cm_ops::CERT_VERIFY_SET_TRUSTED};
    proto::ControlRequestBuilder builder{};
    builder.forDataNodeId(m_context_id).operation(op_id);
    for (const auto& cert : certs)
    {
        builder.with_in_val_uint64(cert.id);
    }
    auto req = builder.build();
    if (!req.has_value())
    {
        return BuildRequestFailure("Failed to build CERT_VERIFY_SET_TRUSTED");
    }
    return SendVerificationRequest(*m_connection, req.value(), op_id);
}

score::Result<std::monostate> CertVerificationContextImpl::SetChainTerminationPolicy(ChainTerminationPolicy policy)
{
    // Request: [0] = ChainTerminationPolicy (uint8).
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_VERIFICATION, cm_ops::CERT_VERIFY_SET_POLICY};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint8(static_cast<std::uint8_t>(policy))
                   .build();
    if (!req.has_value())
    {
        return BuildRequestFailure("Failed to build CERT_VERIFY_SET_POLICY");
    }
    return SendVerificationRequest(*m_connection, req.value(), op_id);
}

score::Result<std::monostate> CertVerificationContextImpl::SetUntrustedCertificates(
    score::cpp::span<const CryptoResourceId> certificates)
{
    // Request: one certificate node id (uint64) per entry. The daemon reads every parameter.
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_VERIFICATION, cm_ops::CERT_VERIFY_SET_UNTRUSTED};
    proto::ControlRequestBuilder builder{};
    builder.forDataNodeId(m_context_id).operation(op_id);
    for (const auto& cert : certificates)
    {
        builder.with_in_val_uint64(cert.id);
    }
    auto req = builder.build();
    if (!req.has_value())
    {
        return BuildRequestFailure("Failed to build CERT_VERIFY_SET_UNTRUSTED");
    }
    return SendVerificationRequest(*m_connection, req.value(), op_id);
}

score::Result<std::monostate> CertVerificationContextImpl::SetVerificationTime(int64_t epoch_seconds)
{
    // Request: [0] = epoch seconds as a uint64 bit pattern; the wire has no signed integer type.
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_VERIFICATION,
                                           cm_ops::CERT_VERIFY_SET_VERIFICATION_TIME};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint64(static_cast<std::uint64_t>(epoch_seconds))
                   .build();
    if (!req.has_value())
    {
        return BuildRequestFailure("Failed to build CERT_VERIFY_SET_VERIFICATION_TIME");
    }
    return SendVerificationRequest(*m_connection, req.value(), op_id);
}

score::Result<std::monostate> CertVerificationContextImpl::SetRevocationCheckPolicy(RevocationCheckPolicy policy)
{
    // Request: [0] = RevocationCheckPolicy (uint8).
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_VERIFICATION,
                                           cm_ops::CERT_VERIFY_SET_REVOCATION_POLICY};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint8(static_cast<std::uint8_t>(policy))
                   .build();
    if (!req.has_value())
    {
        return BuildRequestFailure("Failed to build CERT_VERIFY_SET_REVOCATION_POLICY");
    }
    return SendVerificationRequest(*m_connection, req.value(), op_id);
}

score::Result<std::monostate> CertVerificationContextImpl::SetRevocationCoveragePolicy(RevocationCoveragePolicy policy)
{
    // Request: [0] = RevocationCoveragePolicy (uint8).
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_VERIFICATION,
                                           cm_ops::CERT_VERIFY_SET_REVOCATION_COVERAGE_POLICY};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint8(static_cast<std::uint8_t>(policy))
                   .build();
    if (!req.has_value())
    {
        return BuildRequestFailure("Failed to build CERT_VERIFY_SET_REVOCATION_COVERAGE_POLICY");
    }
    return SendVerificationRequest(*m_connection, req.value(), op_id);
}

score::Result<std::monostate> CertVerificationContextImpl::SetEvidenceMode(VerificationEvidenceMode mode)
{
    // Request: [0] = VerificationEvidenceMode (uint8).
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_VERIFICATION, cm_ops::CERT_VERIFY_SET_EVIDENCE_MODE};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint8(static_cast<std::uint8_t>(mode))
                   .build();
    if (!req.has_value())
    {
        return BuildRequestFailure("Failed to build CERT_VERIFY_SET_EVIDENCE_MODE");
    }
    return SendVerificationRequest(*m_connection, req.value(), op_id);
}

// ===========================================================================
// Execution and verified-evidence queries
// ===========================================================================

score::Result<CertVerifyResult> CertVerificationContextImpl::Verify()
{
    m_verify_result.reset();
    m_chain_count = 0U;

    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_VERIFICATION, cm_ops::CERT_VERIFY};
    auto req = proto::ControlRequestBuilder().forDataNodeId(m_context_id).operation(op_id).build();
    if (!req.has_value())
    {
        return score::Result<CertVerifyResult>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build CERT_VERIFY request")};
    }

    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
    {
        return score::Result<CertVerifyResult>{score::unexpect,
                                               MakeError(GetResponseError(validator), validator.getError())};
    }

    // Response: param[0][0] = uint8 CertVerifyResult, param[0][1] = uint32 certificate count.
    auto result_res = validator.getParameterAt<std::uint8_t>(0, 0);
    if (!result_res.has_value())
    {
        return score::Result<CertVerifyResult>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "CERT_VERIFY response missing result code")};
    }

    auto count_res = validator.getParameterAt<std::uint32_t>(0, 1);
    if (!count_res.has_value())
    {
        return score::Result<CertVerifyResult>{
            score::unexpect,
            MakeError(CryptoErrorCode::kOperationFailed, "CERT_VERIFY response missing certificate count")};
    }

    if (result_res.value() > static_cast<std::uint8_t>(CertVerifyResult::kInvalidPurpose))
    {
        return score::Result<CertVerifyResult>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "CERT_VERIFY returned an invalid result")};
    }

    const auto verify_result = static_cast<CertVerifyResult>(result_res.value());
    m_verify_result = verify_result;
    m_chain_count = count_res.value();
    return verify_result;
}

score::Result<std::size_t> CertVerificationContextImpl::GetVerifiedChainCertificateCount() const
{
    if (!m_verify_result.has_value())
    {
        return score::Result<std::size_t>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Verify() has not been called successfully")};
    }
    return static_cast<std::size_t>(m_chain_count);
}

score::Result<std::size_t> CertVerificationContextImpl::GetVerifiedChainExportSize(FormatType format) const
{
    // Request: [0] = FormatType (uint8). Response: param[0] = uint64 required byte count.
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_VERIFICATION,
                                           cm_ops::CERT_GET_VERIFIED_CHAIN_EXPORT_SIZE};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint8(static_cast<std::uint8_t>(format))
                   .build();
    if (!req.has_value())
    {
        return score::Result<std::size_t>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build chain export size request")};
    }
    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
    {
        return score::Result<std::size_t>{score::unexpect,
                                          MakeError(GetResponseError(validator), validator.getError())};
    }
    auto size = validator.getParameterAt<std::uint64_t>(0, 0);
    if (!size.has_value())
    {
        return score::Result<std::size_t>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Chain export size response missing size")};
    }
    return static_cast<std::size_t>(size.value());
}

score::Result<std::size_t> CertVerificationContextImpl::ExportVerifiedChain(FormatType format,
                                                                            score::cpp::span<uint8_t> out) const
{
    // Request: [0] = FormatType (uint8), [1] = output buffer. Response: the chain is written to the output buffer.
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_VERIFICATION, cm_ops::CERT_EXPORT_VERIFIED_CHAIN};
    proto::OperationRequestBuilder builder;
    builder.operation(op_id).with_in_val_uint8(static_cast<std::uint8_t>(format));
    auto tspan_result = m_transcoder->Acquire(out, /*is_output=*/true);
    if (!tspan_result.has_value())
    {
        return score::Result<std::size_t>{score::unexpect, tspan_result.error()};
    }
    TranscoderSpan tspan = std::move(tspan_result.value());
    m_transcoder->AppendOutputBuffer(builder, tspan);

    auto request_result = MakeControlRequest(std::move(builder), m_context_id);
    if (!request_result.has_value())
    {
        return score::Result<std::size_t>{score::unexpect, request_result.error()};
    }
    auto resp = m_connection->SendRequest(request_result.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
    {
        return score::Result<std::size_t>{score::unexpect,
                                          MakeError(GetResponseError(validator), validator.getError())};
    }
    return m_transcoder->ExtractOutputBuffer(tspan, validator);
}

score::Result<std::size_t> CertVerificationContextImpl::GetVerifiedCertificateExportSize(std::size_t index,
                                                                                         FormatType format) const
{
    // Request: [0] = index (uint64), [1] = FormatType (uint8). Response: param[0] = uint64 required byte count.
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_VERIFICATION,
                                           cm_ops::CERT_GET_VERIFIED_CERT_EXPORT_SIZE};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint64(static_cast<std::uint64_t>(index))
                   .with_in_val_uint8(static_cast<std::uint8_t>(format))
                   .build();
    if (!req.has_value())
    {
        return score::Result<std::size_t>{
            score::unexpect,
            MakeError(CryptoErrorCode::kOperationFailed, "Failed to build certificate export size request")};
    }
    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
    {
        return score::Result<std::size_t>{score::unexpect,
                                          MakeError(GetResponseError(validator), validator.getError())};
    }
    auto size = validator.getParameterAt<std::uint64_t>(0, 0);
    if (!size.has_value())
    {
        return score::Result<std::size_t>{
            score::unexpect,
            MakeError(CryptoErrorCode::kOperationFailed, "Certificate export size response missing size")};
    }
    return static_cast<std::size_t>(size.value());
}

score::Result<std::size_t> CertVerificationContextImpl::ExportVerifiedCertificate(std::size_t index,
                                                                                  FormatType format,
                                                                                  score::cpp::span<uint8_t> out) const
{
    // Request: [0] = index (uint64), [1] = FormatType (uint8), [2] = output buffer.
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_VERIFICATION, cm_ops::CERT_EXPORT_VERIFIED_CERT};
    proto::OperationRequestBuilder builder;
    builder.operation(op_id)
        .with_in_val_uint64(static_cast<std::uint64_t>(index))
        .with_in_val_uint8(static_cast<std::uint8_t>(format));
    auto tspan_result = m_transcoder->Acquire(out, /*is_output=*/true);
    if (!tspan_result.has_value())
    {
        return score::Result<std::size_t>{score::unexpect, tspan_result.error()};
    }
    TranscoderSpan tspan = std::move(tspan_result.value());
    m_transcoder->AppendOutputBuffer(builder, tspan);

    auto request_result = MakeControlRequest(std::move(builder), m_context_id);
    if (!request_result.has_value())
    {
        return score::Result<std::size_t>{score::unexpect, request_result.error()};
    }
    auto resp = m_connection->SendRequest(request_result.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
    {
        return score::Result<std::size_t>{score::unexpect,
                                          MakeError(GetResponseError(validator), validator.getError())};
    }
    return m_transcoder->ExtractOutputBuffer(tspan, validator);
}

score::Result<std::size_t> CertVerificationContextImpl::GetSelectedCrlMetadataCount() const
{
    // Response: param[0] = uint64 number of selected CRLs.
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_VERIFICATION, cm_ops::CERT_GET_SELECTED_CRL_METADATA};
    proto::OperationRequestBuilder builder;
    builder.operation(op_id);
    auto request_result = MakeControlRequest(std::move(builder), m_context_id);
    if (!request_result.has_value())
    {
        return score::Result<std::size_t>{score::unexpect, request_result.error()};
    }
    auto resp = m_connection->SendRequest(request_result.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
    {
        return score::Result<std::size_t>{score::unexpect,
                                          MakeError(GetResponseError(validator), validator.getError())};
    }
    auto count = validator.getParameterAt<std::uint64_t>(0, 0);
    if (!count.has_value())
    {
        return score::Result<std::size_t>{
            score::unexpect,
            MakeError(CryptoErrorCode::kOperationFailed, "Selected CRL metadata count response missing count")};
    }
    return static_cast<std::size_t>(count.value());
}

score::Result<std::size_t> CertVerificationContextImpl::GetSelectedCrlMetadata(score::cpp::span<CrlMetadata> out) const
{
    using Layout = daemon::cert_management::CrlMetadataWireLayout;
    // Entries travel in the CrlMetadataWireLayout encoding. The daemon writes into a byte buffer that is decoded
    // entry by entry once the response has been validated.
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_VERIFICATION, cm_ops::CERT_GET_SELECTED_CRL_METADATA};
    std::vector<uint8_t> encoded(out.size() * Layout::kEntrySize);
    score::cpp::span<uint8_t> output_bytes{encoded.data(), encoded.size()};

    proto::OperationRequestBuilder builder;
    builder.operation(op_id);
    auto tspan_result = m_transcoder->Acquire(output_bytes, /*is_output=*/true);
    if (!tspan_result.has_value())
    {
        return score::Result<std::size_t>{score::unexpect, tspan_result.error()};
    }
    TranscoderSpan tspan = std::move(tspan_result.value());
    m_transcoder->AppendOutputBuffer(builder, tspan);

    auto request_result = MakeControlRequest(std::move(builder), m_context_id);
    if (!request_result.has_value())
    {
        return score::Result<std::size_t>{score::unexpect, request_result.error()};
    }
    auto resp = m_connection->SendRequest(request_result.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
    {
        return score::Result<std::size_t>{score::unexpect,
                                          MakeError(GetResponseError(validator), validator.getError())};
    }
    // Response: param[0] = uint64 entry count; the encoded entries are the output buffer at param[1].
    auto count = validator.getParameterAt<std::uint64_t>(0, 0);
    if (!count.has_value())
    {
        return score::Result<std::size_t>{
            score::unexpect,
            MakeError(CryptoErrorCode::kOperationFailed, "Selected CRL metadata response missing count")};
    }
    auto bytes_written = m_transcoder->ExtractOutputBuffer(tspan, validator, 1U);
    if (!bytes_written.has_value())
    {
        return score::Result<std::size_t>{score::unexpect, bytes_written.error()};
    }
    const auto entry_count = static_cast<std::size_t>(count.value());
    if (bytes_written.value() != entry_count * Layout::kEntrySize)
    {
        return score::Result<std::size_t>{
            score::unexpect,
            MakeError(CryptoErrorCode::kOperationFailed, "Selected CRL metadata buffer size is invalid")};
    }
    if (out.size() < entry_count)
    {
        return score::Result<std::size_t>{
            score::unexpect,
            MakeError(CryptoErrorCode::kOperationFailed, "Selected CRL metadata output span too small")};
    }
    for (std::size_t i = 0U; i < entry_count; ++i)
    {
        const uint8_t* entry = encoded.data() + i * Layout::kEntrySize;
        CrlMetadata metadata{};
        if (!Layout::Decode(score::cpp::span<const uint8_t>{entry, Layout::kEntrySize}, metadata))
        {
            return score::Result<std::size_t>{
                score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Selected CRL metadata is malformed")};
        }
        out[i] = metadata;
    }
    return entry_count;
}

}  // namespace crypto

}  // namespace score

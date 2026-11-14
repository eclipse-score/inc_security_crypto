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

#include "score/crypto/src/api/objects/src/certificate_object_impl.hpp"

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"

#include <cstdint>
#include <string>
#include <utility>

namespace score
{

namespace crypto
{

namespace
{

namespace proto = ::score::crypto::daemon::control_plane::protocol;

// Wraps an operation in a control request addressed to the node of the given connection.
score::Result<proto::ControlRequest> MakeConnectionRequest(proto::OperationRequestBuilder builder,
                                                           proto::DataNodeId connection_node_id)
{
    auto operation_result = builder.build();
    if (!operation_result.has_value())
    {
        return score::Result<proto::ControlRequest>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build public key request")};
    }

    proto::ControlRequest request{};
    request.operation = operation_result.value();
    request.data_node_id = connection_node_id;
    return request;
}

}  // namespace

CertificateObjectImpl::CertificateObjectImpl(CryptoResourceId id,
                                             std::string subject,
                                             std::string issuer,
                                             std::string serial_number,
                                             std::array<uint8_t, kSha256FingerprintSize> fingerprint,
                                             int64_t not_before,
                                             int64_t not_after,
                                             std::optional<CrlMetadata> crl_metadata,
                                             std::shared_ptr<api::control_plane::IConnection> connection,
                                             std::shared_ptr<IBufferTranscoder> transcoder,
                                             std::size_t public_key_size,
                                             std::string public_key_algorithm)
    : m_id(id),
      m_subject(std::move(subject)),
      m_issuer(std::move(issuer)),
      m_serial_number(std::move(serial_number)),
      m_fingerprint(fingerprint),
      m_not_before(not_before),
      m_not_after(not_after),
      m_crl_metadata(std::move(crl_metadata)),
      m_connection(std::move(connection)),
      m_transcoder(std::move(transcoder)),
      m_public_key_size(public_key_size),
      m_public_key_algorithm(public_key_algorithm)
{
}

CryptoResourceId CertificateObjectImpl::GetId() const noexcept
{
    return m_id;
}

ResourceType CertificateObjectImpl::GetType() const noexcept
{
    return ResourceType::kCertificate;
}

std::string_view CertificateObjectImpl::GetSubject() const noexcept
{
    return m_subject;
}

std::string_view CertificateObjectImpl::GetIssuer() const noexcept
{
    return m_issuer;
}

int64_t CertificateObjectImpl::GetNotBefore() const noexcept
{
    return m_not_before;
}

int64_t CertificateObjectImpl::GetNotAfter() const noexcept
{
    return m_not_after;
}

AlgorithmId CertificateObjectImpl::GetPublicKeyAlgorithm() const noexcept
{
    return m_public_key_algorithm;
}

std::string CertificateObjectImpl::GetSerialNumber() const
{
    return m_serial_number;
}

std::array<uint8_t, kSha256FingerprintSize> CertificateObjectImpl::GetFingerprint() const noexcept
{
    return m_fingerprint;
}

std::optional<CrlMetadata> CertificateObjectImpl::GetCrlMetadata() const noexcept
{
    return m_crl_metadata;
}

score::Result<std::size_t> CertificateObjectImpl::GetPublicKeyExportSize() const noexcept
{
    if (m_public_key_size == 0U)
    {
        return score::Result<std::size_t>{
            score::unexpect,
            MakeError(CryptoErrorCode::kUnsupportedAlgorithm,
                      "Public key is not available: its algorithm is not supported by the provider")};
    }
    return m_public_key_size;
}

score::Result<std::size_t> CertificateObjectImpl::ExportPublicKey(score::cpp::span<uint8_t> output) const
{
    namespace med_ops = ::score::crypto::daemon::mediator::operations;

    if (m_public_key_size == 0U)
    {
        return score::Result<std::size_t>{
            score::unexpect,
            MakeError(CryptoErrorCode::kUnsupportedAlgorithm,
                      "Public key is not available: its algorithm is not supported by the provider")};
    }
    if (output.size() < m_public_key_size)
    {
        return score::Result<std::size_t>{
            score::unexpect,
            MakeError(CryptoErrorCode::kInsufficientBufferSize, "Output buffer is smaller than the public key")};
    }

    // Request: [0]=certificate node id (uint64), [1]=expected SHA-256 fingerprint (data buffer), [2]=output buffer
    // Response: [0][0]=uint64 bytes written
    const proto::OperationIdentifier op_id = med_ops::GetCertificatePublicKey();
    proto::OperationRequestBuilder builder;
    builder.operation(op_id).with_in_val_uint64(m_id.id).with_in_data_buffer(
        score::cpp::span<const uint8_t>{m_fingerprint.data(), m_fingerprint.size()});
    auto tspan_result = m_transcoder->Acquire(output, /*is_output=*/true);
    if (!tspan_result.has_value())
    {
        return score::Result<std::size_t>{score::unexpect, tspan_result.error()};
    }
    TranscoderSpan tspan = std::move(tspan_result.value());
    m_transcoder->AppendOutputBuffer(builder, tspan);

    auto request_result = MakeConnectionRequest(std::move(builder), m_connection->GetConnectionNodeId());
    if (!request_result.has_value())
    {
        return score::Result<std::size_t>{score::unexpect, request_result.error()};
    }
    auto resp = m_connection->SendRequest(request_result.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
    {
        return score::Result<std::size_t>{
            score::unexpect,
            MakeError(validator.getOperationError().value_or(CryptoErrorCode::kOperationFailed), validator.getError())};
    }
    return m_transcoder->ExtractOutputBuffer(tspan, validator);
}

}  // namespace crypto

}  // namespace score

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

#include "score/crypto/src/daemon/cert_management/query/get_certificate_public_key_query.hpp"

#include "score/crypto/src/daemon/cert_management/interfaces/cert_types.hpp"

#include "score/mw/log/logging.h"

#include <algorithm>
#include <cstdint>
#include <string_view>
#include <utility>

namespace score::crypto::daemon::cert_management::query
{

namespace
{

constexpr std::string_view kLogPrefix = "[CERT_PUBLIC_KEY_QUERY] ";

}  // namespace

GetCertificatePublicKeyQuery::GetCertificatePublicKeyQuery(CertManagementService::Sptr service) noexcept
    : m_service(std::move(service))
{
}

bool GetCertificatePublicKeyQuery::Handle(const control_plane::protocol::ControlRequest& request,
                                          const control_plane::protocol::SingleOperationRequest& operation,
                                          control_plane::protocol::OperationResponseBuilder& responseBuilder)
{
    const auto node_id = operation.getParameter<std::uint64_t>(0U);
    if (!node_id.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "GET_CERTIFICATE_PUBLIC_KEY: missing node id parameter";
        responseBuilder.operation(operation.operationId).return_error(node_id.error());
        return false;
    }

    const auto fingerprint = operation.getParameter<score::crypto::span<const std::uint8_t>>(1U);
    if (!fingerprint.has_value() || fingerprint.value().size() != score::crypto::kSha256FingerprintSize)
    {
        score::mw::log::LogError() << kLogPrefix << "GET_CERTIFICATE_PUBLIC_KEY: missing or malformed fingerprint";
        responseBuilder.operation(operation.operationId).return_error(common::DaemonErrorCode::kInvalidArgument);
        return false;
    }

    const auto output = operation.getParameter<score::crypto::span<std::uint8_t>>(2U);
    if (!output.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "GET_CERTIFICATE_PUBLIC_KEY: missing output buffer";
        responseBuilder.operation(operation.operationId).return_error(output.error());
        return false;
    }
    const auto& buffer = output.value();
    if (buffer.data() == nullptr || buffer.size() == 0U)
    {
        score::mw::log::LogError() << kLogPrefix << "GET_CERTIFICATE_PUBLIC_KEY: output buffer is empty";
        responseBuilder.operation(operation.operationId).return_error(common::DaemonErrorCode::kInsufficientBufferSize);
        return false;
    }

    const auto resolved = m_service->ResolveCertObjectWithCrlMetadata(request.client_id, node_id.value());
    if (!resolved.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "GET_CERTIFICATE_PUBLIC_KEY: resolution failed";
        responseBuilder.operation(operation.operationId).return_error(resolved.error());
        return false;
    }

    const auto& cert = resolved.value().cert;
    if (!cert)
    {
        score::mw::log::LogError() << kLogPrefix << "GET_CERTIFICATE_PUBLIC_KEY: resolved node has no certificate";
        responseBuilder.operation(operation.operationId).return_error(common::DaemonErrorCode::kInternalError);
        return false;
    }

    const auto& meta = cert->GetChainMetadata();
    if (!std::equal(fingerprint.value().begin(), fingerprint.value().end(), meta.fingerprint.begin()))
    {
        score::mw::log::LogError() << kLogPrefix
                                   << "GET_CERTIFICATE_PUBLIC_KEY: node no longer holds the expected certificate";
        responseBuilder.operation(operation.operationId).return_error(common::DaemonErrorCode::kResourceNotFound);
        return false;
    }

    const auto& key = meta.public_key_der;
    if (buffer.size() < key.size())
    {
        responseBuilder.operation(operation.operationId).return_error(common::DaemonErrorCode::kInsufficientBufferSize);
        return false;
    }
    std::copy(key.begin(), key.end(), buffer.begin());

    common::ResponseParameters params;
    params.push_back(static_cast<std::uint64_t>(key.size()));
    responseBuilder.return_crypto_operation_response(
        operation.operationId, control_plane::protocol::OPERATION_RESULT_SUCCESS, std::move(params));
    return true;
}

}  // namespace score::crypto::daemon::cert_management::query

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

#include "score/crypto/src/daemon/cert_management/query/get_certificate_object_query.hpp"

#include "score/crypto/src/daemon/cert_management/query/cert_object_response_builder.hpp"

#include "score/mw/log/logging.h"

#include <cstdint>
#include <string_view>
#include <utility>

namespace score::crypto::daemon::cert_management::query
{

namespace
{

constexpr std::string_view kLogPrefix = "[CERT_OBJECT_QUERY] ";

}  // namespace

GetCertificateObjectQuery::GetCertificateObjectQuery(CertManagementService::Sptr service) noexcept
    : m_service(std::move(service))
{
}

bool GetCertificateObjectQuery::Handle(const control_plane::protocol::ControlRequest& request,
                                       const control_plane::protocol::SingleOperationRequest& operation,
                                       control_plane::protocol::OperationResponseBuilder& responseBuilder)
{
    const auto node_id = operation.getParameter<std::uint64_t>(0U);
    if (!node_id.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "GET_CERTIFICATE_OBJECT: missing node id parameter";
        responseBuilder.operation(operation.operationId).return_error(node_id.error());
        return false;
    }

    const auto resolved = m_service->ResolveCertObjectWithCrlMetadata(request.client_id, node_id.value());
    if (!resolved.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "GET_CERTIFICATE_OBJECT: resolution failed";
        responseBuilder.operation(operation.operationId).return_error(resolved.error());
        return false;
    }

    const auto& object = resolved.value();
    if (!object.cert)
    {
        score::mw::log::LogError() << kLogPrefix << "GET_CERTIFICATE_OBJECT: resolved node has no certificate";
        responseBuilder.operation(operation.operationId).return_error(common::DaemonErrorCode::kInternalError);
        return false;
    }

    auto params = BuildCertObjectResponse(*object.cert, object.crl_metadata);
    if (!params.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "GET_CERTIFICATE_OBJECT: response build failed";
        responseBuilder.operation(operation.operationId).return_error(params.error());
        return false;
    }

    responseBuilder.return_crypto_operation_response(
        operation.operationId, control_plane::protocol::OPERATION_RESULT_SUCCESS, std::move(params.value()));
    return true;
}

}  // namespace score::crypto::daemon::cert_management::query

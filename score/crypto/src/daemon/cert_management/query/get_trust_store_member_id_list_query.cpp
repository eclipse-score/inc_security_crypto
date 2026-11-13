/*******************************************************************************
 *
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
 *******************************************************************************
 */

#include "score/crypto/src/daemon/cert_management/query/get_trust_store_member_id_list_query.hpp"

#include "score/crypto/src/daemon/cert_management/query/cert_object_response_builder.hpp"

#include "score/mw/log/logging.h"

#include <cstdint>
#include <string_view>
#include <utility>

namespace score::crypto::daemon::cert_management::query
{

namespace
{

constexpr std::string_view kLogPrefix = "[TRUST_STORE_QUERY] ";

}  // namespace

GetTrustStoreMemberIdListQuery::GetTrustStoreMemberIdListQuery(CertManagementService::Sptr service) noexcept
    : m_service(std::move(service))
{
}

bool GetTrustStoreMemberIdListQuery::Handle(const control_plane::protocol::ControlRequest& request,
                                            const control_plane::protocol::SingleOperationRequest& operation,
                                            control_plane::protocol::OperationResponseBuilder& responseBuilder)
{
    const auto node_id = operation.getParameter<std::uint64_t>(0U);
    if (!node_id.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "GET_TRUST_STORE_MEMBER_ID_LIST: missing trust-store node id";
        responseBuilder.operation(operation.operationId).return_error(node_id.error());
        return false;
    }

    const auto trust_store = m_service->ResolveTrustStoreHandle(request.client_id, node_id.value());
    if (!trust_store.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "GET_TRUST_STORE_MEMBER_ID_LIST: resolution failed";
        responseBuilder.operation(operation.operationId).return_error(trust_store.error());
        return false;
    }

    const auto slots = m_service->GetTrustStoreManager()->GetMemberSlotHandles(trust_store.value());
    if (!slots.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "GET_TRUST_STORE_MEMBER_ID_LIST: member listing failed";
        responseBuilder.operation(operation.operationId).return_error(slots.error());
        return false;
    }

    auto params = BuildTrustStoreMemberIdListResponse(slots.value(), *m_service, request.client_id);
    if (!params.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "GET_TRUST_STORE_MEMBER_ID_LIST: response build failed";
        responseBuilder.operation(operation.operationId).return_error(params.error());
        return false;
    }

    responseBuilder.return_crypto_operation_response(
        operation.operationId, control_plane::protocol::OPERATION_RESULT_SUCCESS, std::move(params.value()));
    return true;
}

}  // namespace score::crypto::daemon::cert_management::query

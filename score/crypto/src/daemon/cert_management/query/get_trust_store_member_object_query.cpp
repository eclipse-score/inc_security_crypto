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

#include "score/crypto/src/daemon/cert_management/query/get_trust_store_member_object_query.hpp"

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

GetTrustStoreMemberObjectQuery::GetTrustStoreMemberObjectQuery(CertManagementService::Sptr service) noexcept
    : m_service(std::move(service))
{
}

bool GetTrustStoreMemberObjectQuery::Handle(const control_plane::protocol::ControlRequest& request,
                                            const control_plane::protocol::SingleOperationRequest& operation,
                                            control_plane::protocol::OperationResponseBuilder& responseBuilder)
{
    const auto trust_store_node = operation.getParameter<std::uint64_t>(0U);
    if (!trust_store_node.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "GET_TRUST_STORE_MEMBER_OBJECT: missing trust-store node id";
        responseBuilder.operation(operation.operationId).return_error(trust_store_node.error());
        return false;
    }
    const auto slot_node = operation.getParameter<std::uint64_t>(1U);
    if (!slot_node.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "GET_TRUST_STORE_MEMBER_OBJECT: missing member slot node id";
        responseBuilder.operation(operation.operationId).return_error(slot_node.error());
        return false;
    }

    const auto trust_store = m_service->ResolveTrustStoreHandle(request.client_id, trust_store_node.value());
    if (!trust_store.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "GET_TRUST_STORE_MEMBER_OBJECT: trust-store resolution failed";
        responseBuilder.operation(operation.operationId).return_error(trust_store.error());
        return false;
    }
    const auto slot = m_service->ResolveCertSlotHandle(request.client_id, slot_node.value());
    if (!slot.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "GET_TRUST_STORE_MEMBER_OBJECT: member slot resolution failed";
        responseBuilder.operation(operation.operationId).return_error(slot.error());
        return false;
    }

    const auto member = m_service->GetTrustStoreManager()->GetMemberSnapshot(trust_store.value(), slot.value());
    if (!member.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "GET_TRUST_STORE_MEMBER_OBJECT: member snapshot failed";
        responseBuilder.operation(operation.operationId).return_error(member.error());
        return false;
    }

    auto params = BuildTrustStoreMemberObjectResponse(member.value(), slot_node.value());
    if (!params.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "GET_TRUST_STORE_MEMBER_OBJECT: response build failed";
        responseBuilder.operation(operation.operationId).return_error(params.error());
        return false;
    }

    responseBuilder.return_crypto_operation_response(
        operation.operationId, control_plane::protocol::OPERATION_RESULT_SUCCESS, std::move(params.value()));
    return true;
}

}  // namespace score::crypto::daemon::cert_management::query

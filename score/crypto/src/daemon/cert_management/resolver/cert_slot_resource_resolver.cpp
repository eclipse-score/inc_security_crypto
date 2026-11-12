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

#include "score/crypto/src/daemon/cert_management/resolver/cert_slot_resource_resolver.hpp"

#include "score/crypto/src/api/types/common.hpp"

#include <cstdint>
#include <string>
#include <utility>

namespace score::crypto::daemon::cert_management
{

CertSlotResourceResolver::CertSlotResourceResolver(CertManagementService::Sptr service) noexcept
    : m_service(std::move(service))
{
}

bool CertSlotResourceResolver::Resolve(std::uint64_t client_id,
                                       std::uint64_t /*session_id*/,
                                       const std::string& resource_name,
                                       const common::OperationIdentifier& op_id,
                                       control_plane::protocol::OperationResponseBuilder& responseBuilder)
{
    const auto node_id = m_service->ResolveCertSlotNode(resource_name, client_id);
    if (!node_id.has_value())
    {
        responseBuilder.operation(op_id).return_error(node_id.error());
        return false;
    }

    responseBuilder.operation(op_id)
        .return_value_uint64(static_cast<std::uint64_t>(node_id.value()))
        .return_value_uint8(static_cast<std::uint8_t>(score::crypto::ResourceType::kCertSlot))
        .return_value_bool(true)  // Certificate slots are persistent.
        .return_value_uint16(0U)
        .return_success();
    return true;
}

}  // namespace score::crypto::daemon::cert_management

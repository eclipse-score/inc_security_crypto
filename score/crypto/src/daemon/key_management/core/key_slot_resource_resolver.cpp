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

#include "score/crypto/src/daemon/key_management/core/key_slot_resource_resolver.hpp"

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/types/common.hpp"

#include <cstdint>
#include <string>
#include <utility>

namespace score::crypto::daemon::key_management
{

KeySlotResourceResolver::KeySlotResourceResolver(KeyManagementService::Sptr km_service) noexcept
    : m_km_service(std::move(km_service))
{
}

bool KeySlotResourceResolver::Resolve(std::uint64_t client_id,
                                      std::uint64_t /*session_id*/,
                                      const std::string& resource_name,
                                      const common::OperationIdentifier& op_id,
                                      control_plane::protocol::OperationResponseBuilder& responseBuilder)
{
    auto node_id_result = m_km_service->ResolveKeySlot(resource_name, client_id);
    if (!node_id_result.has_value())
    {
        responseBuilder.operation(op_id).return_error(score::crypto::CryptoErrorCode::kInternalError);
        return false;
    }

    // The primary provider of a key slot is not tracked yet; 0 is returned in its place.
    responseBuilder.operation(op_id)
        .return_value_uint64(static_cast<std::uint64_t>(node_id_result.value()))
        .return_value_uint8(static_cast<std::uint8_t>(score::crypto::ResourceType::kKeySlot))
        .return_value_bool(true)  // Key slots are always persistent.
        .return_value_uint16(0)
        .return_success();
    return true;
}

}  // namespace score::crypto::daemon::key_management

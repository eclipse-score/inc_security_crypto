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

#ifndef SCORE_CRYPTO_SRC_DAEMON_KEY_MANAGEMENT_CORE_KEY_SLOT_RESOURCE_RESOLVER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_KEY_MANAGEMENT_CORE_KEY_SLOT_RESOURCE_RESOLVER_HPP

#include "score/crypto/src/daemon/common/context/i_resource_resolver.hpp"
#include "score/crypto/src/daemon/key_management/core/key_management_service.hpp"

#include <cstdint>
#include <string>

namespace score::crypto::daemon::key_management
{

/// @brief Resolves application key-slot names to session-scoped key-slot data nodes.
///
/// The resolved DataNodeId is returned to the client as an opaque handle. The DataManager
/// enforces it per session, and it does not expose the registry index of the slot.
class KeySlotResourceResolver final : public common::IResourceResolver
{
  public:
    /// @brief Create a resolver backed by a key management service.
    /// @param km_service Service that resolves key-slot names. Must not be null.
    explicit KeySlotResourceResolver(KeyManagementService::Sptr km_service) noexcept;

    /// @brief Resolve a key-slot name for a client and write its handle to the response.
    /// @return True if the name resolved to a key slot.
    [[nodiscard]] bool Resolve(std::uint64_t client_id,
                               std::uint64_t session_id,
                               const std::string& resource_name,
                               const common::OperationIdentifier& op_id,
                               control_plane::protocol::OperationResponseBuilder& responseBuilder) override;

  private:
    KeyManagementService::Sptr m_km_service;
};

}  // namespace score::crypto::daemon::key_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_KEY_MANAGEMENT_CORE_KEY_SLOT_RESOURCE_RESOLVER_HPP

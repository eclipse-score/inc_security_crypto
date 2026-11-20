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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_RESOLVER_TRUST_STORE_RESOURCE_RESOLVER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_RESOLVER_TRUST_STORE_RESOURCE_RESOLVER_HPP

#include "score/crypto/src/daemon/cert_management/core/cert_management_service.hpp"
#include "score/crypto/src/daemon/common/context/i_resource_resolver.hpp"

#include <cstdint>
#include <string>

namespace score::crypto::daemon::cert_management
{

/// @brief Resolves application trust-store names to session-scoped trust-store data nodes.
///
/// The resolved DataNodeId is returned to the client as an opaque handle. The DataManager enforces it per session, and
/// it does not expose the registry index of the trust store.
class TrustStoreResourceResolver final : public common::IResourceResolver
{
  public:
    /// @brief Create a resolver backed by a certificate-management service.
    /// @param service Service that resolves trust-store names. Must not be null.
    explicit TrustStoreResourceResolver(CertManagementService::Sptr service) noexcept;

    /// @brief Resolve a trust-store name for a client and write its handle to the response.
    /// @return True if the name resolved to a trust store.
    [[nodiscard]] bool Resolve(std::uint64_t client_id,
                               std::uint64_t session_id,
                               const std::string& resource_name,
                               const common::OperationIdentifier& op_id,
                               control_plane::protocol::OperationResponseBuilder& responseBuilder) override;

  private:
    CertManagementService::Sptr m_service;
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_RESOLVER_TRUST_STORE_RESOURCE_RESOLVER_HPP

/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/
#ifndef SCORE_CRYPTO_SRC_API_CONTROL_PLANE_CONTROL_PLANE_CONNECTION_REGISTRY_HPP
#define SCORE_CRYPTO_SRC_API_CONTROL_PLANE_CONTROL_PLANE_CONNECTION_REGISTRY_HPP

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/control_plane/src/control_plane_connection.hpp"

#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>

namespace score::crypto::api::control_plane
{

/// @brief Shares established daemon connections among API control-plane callers.
/// @details Entries are weakly owned so unused endpoint connections can be released.
class ControlPlaneConnectionRegistry final
{
  public:
    using Connection = std::shared_ptr<ControlPlaneConnection>;
    using Result = score::crypto::Expected<Connection, score::crypto::CryptoErrorCode>;

    /// @brief Returns the process-wide connection registry.
    /// @return The singleton registry instance.
    static ControlPlaneConnectionRegistry& Instance() noexcept;

    /// @brief Reuses or establishes a connection to a daemon endpoint.
    /// @param service_identifier Endpoint identifying the daemon service.
    /// @return A shared connection, or an error if establishment fails.
    Result EstablishConnection(std::string_view service_identifier);

  private:
    /// Constructs the process-wide registry on first access.
    ControlPlaneConnectionRegistry() = default;
    /// Releases the registry when the process shuts down.
    ~ControlPlaneConnectionRegistry() = default;

    ControlPlaneConnectionRegistry(const ControlPlaneConnectionRegistry&) = delete;
    ControlPlaneConnectionRegistry& operator=(const ControlPlaneConnectionRegistry&) = delete;
    ControlPlaneConnectionRegistry(ControlPlaneConnectionRegistry&&) = default;
    ControlPlaneConnectionRegistry& operator=(ControlPlaneConnectionRegistry&&) = default;

    std::mutex m_mutex;
    std::unordered_map<std::string, std::weak_ptr<ControlPlaneConnection>> m_connections;
    std::unordered_map<std::string, std::shared_ptr<std::mutex>> m_establishment_mutexes;
};

}  // namespace score::crypto::api::control_plane

#endif  // SCORE_CRYPTO_SRC_API_CONTROL_PLANE_CONTROL_PLANE_CONNECTION_REGISTRY_HPP

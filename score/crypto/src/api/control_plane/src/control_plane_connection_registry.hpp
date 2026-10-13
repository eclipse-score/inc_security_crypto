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

class ControlPlaneConnectionRegistry final
{
  public:
    using Connection = std::shared_ptr<ControlPlaneConnection>;
    using Result = score::crypto::Expected<Connection, score::crypto::CryptoErrorCode>;

    static ControlPlaneConnectionRegistry& Instance() noexcept;
    Result EstablishConnection(std::string_view service_identifier);

  private:
    ControlPlaneConnectionRegistry() = default;
    ~ControlPlaneConnectionRegistry() = default;

    ControlPlaneConnectionRegistry(const ControlPlaneConnectionRegistry&) = delete;
    ControlPlaneConnectionRegistry& operator=(const ControlPlaneConnectionRegistry&) = delete;
    ControlPlaneConnectionRegistry(ControlPlaneConnectionRegistry&&) = default;
    ControlPlaneConnectionRegistry& operator=(ControlPlaneConnectionRegistry&&) = default;

    std::mutex mutex_;
    std::unordered_map<std::string, std::weak_ptr<ControlPlaneConnection>> connections_;
    std::unordered_map<std::string, std::shared_ptr<std::mutex>> establishment_mutexes_;
};

}  // namespace score::crypto::api::control_plane

#endif  // SCORE_CRYPTO_SRC_API_CONTROL_PLANE_CONTROL_PLANE_CONNECTION_REGISTRY_HPP

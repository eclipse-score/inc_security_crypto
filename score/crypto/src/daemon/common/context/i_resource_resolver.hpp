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

#ifndef SCORE_CRYPTO_SRC_DAEMON_COMMON_CONTEXT_I_RESOURCE_RESOLVER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_COMMON_CONTEXT_I_RESOURCE_RESOLVER_HPP

#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"

#include <cstdint>
#include <memory>
#include <string>

namespace score::crypto::daemon::common
{

/// @brief Resolves a named application resource of one ResourceType for a client.
///
/// A resolver is registered under the ResourceType it serves. The mediator selects it for a
/// RESOLVE_RESOURCE request of that type and passes the resolved resource back through the
/// response builder.
///
/// Implementations are called from connection threads and must be thread-safe.
class IResourceResolver
{
  public:
    /// @brief Shared pointer to a resource resolver.
    using Sptr = std::shared_ptr<IResourceResolver>;

    /// @brief Virtual destructor.
    virtual ~IResourceResolver() = default;

    /// @brief Resolve a resource and write the result to the response.
    /// @param client_id Client requesting the resource.
    /// @param session_id Session in which the resource is resolved.
    /// @param resource_name Application-defined resource name.
    /// @param op_id Identifier of the resolution operation.
    /// @param responseBuilder Builder receiving the resolved resource or an error.
    /// @return True if the resource was resolved.
    [[nodiscard]] virtual bool Resolve(std::uint64_t client_id,
                                       std::uint64_t session_id,
                                       const std::string& resource_name,
                                       const OperationIdentifier& op_id,
                                       control_plane::protocol::OperationResponseBuilder& responseBuilder) = 0;
};

}  // namespace score::crypto::daemon::common

#endif  // SCORE_CRYPTO_SRC_DAEMON_COMMON_CONTEXT_I_RESOURCE_RESOLVER_HPP

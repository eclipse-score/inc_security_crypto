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

#ifndef SCORE_CRYPTO_SRC_DAEMON_COMMON_CONTEXT_I_CONTEXT_FACTORY_HPP
#define SCORE_CRYPTO_SRC_DAEMON_COMMON_CONTEXT_I_CONTEXT_FACTORY_HPP

#include "score/crypto/src/daemon/common/context/context_creation_request.hpp"
#include "score/crypto/src/daemon/common/context/i_handler.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"

#include <memory>

namespace score::crypto::daemon::common
{

/// @brief Creates the handler for a context type that a subsystem serves directly.
///
/// A factory is registered for one context type and creates a new handler for each CTX_CREATE of
/// that type. The mediator then creates and initializes the context node itself.
///
/// The mediator selects no provider for such a context. The request carries the client's provider
/// preference, and a factory that needs provider-specific work selects the provider with it.
///
/// The mediator does not bind a key for a factory-served context. Key authorization is decided per
/// context type, and a factory-served type defines no required permission, so a key could not be
/// checked. A request that references a key is therefore refused before `Create` is called. A
/// context that needs a key later, for example one that is given its key after creation, holds the
/// key reference and has each internal context it opens bind and authorize the key itself.
///
/// Implementations are called from connection threads and must be thread-safe.
class IContextFactory
{
  public:
    /// @brief Shared pointer to a context factory.
    using Sptr = std::shared_ptr<IContextFactory>;

    /// @brief Virtual destructor.
    virtual ~IContextFactory() = default;

    /// @brief Create the handler for a validated request.
    /// @param request Validated CTX_CREATE request; its views are valid for the duration of the call.
    /// @return The new handler, or the error returned to the client.
    [[nodiscard]] virtual Expected<Handler::Sptr, DaemonErrorCode> Create(const ContextCreationRequest& request) = 0;
};

}  // namespace score::crypto::daemon::common

#endif  // SCORE_CRYPTO_SRC_DAEMON_COMMON_CONTEXT_I_CONTEXT_FACTORY_HPP

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

#ifndef CRYPTO_DAEMON_PROVIDER_HANDLER_HANDLER_HPP
#define CRYPTO_DAEMON_PROVIDER_HANDLER_HANDLER_HPP
#include "score/crypto/common/types.hpp"
#include "score/crypto/daemon/common/daemon_error.hpp"
#include "score/crypto/daemon/common/types.hpp"
#include "score/crypto/daemon/provider/handler/handler_init_params.hpp"
#include <memory>

namespace score::crypto::daemon::provider::handler
{

class Handler
{
  public:
    using Sptr = std::shared_ptr<Handler>;
    virtual ~Handler() = default;

    /// Initialise the handler with runtime context supplied by the mediator at
    /// CTX_CREATE time.  The handler's algorithm and capabilities are already
    /// fixed at construction — this method wires the per-request identity and
    /// optional bound key handle.
    virtual Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode> InitializeContext(
        const handler::InitializationParams& init_params) = 0;
    virtual Expected<common::ResponseParameters, ::score::crypto::daemon::common::DaemonErrorCode> Execute(
        const common::OperationIdentifier& operationId,
        common::RequestParameters& request) = 0;
    virtual Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode> Reset() = 0;
};

}  // namespace score::crypto::daemon::provider::handler

#endif  // CRYPTO_DAEMON_PROVIDER_HANDLER_HANDLER_HPP

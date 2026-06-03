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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_EXECUTORS_KEY_MGMT_CONTEXT_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_EXECUTORS_KEY_MGMT_CONTEXT_HPP

#include "score/crypto/daemon/common/types.hpp"

#include <cstdint>

namespace score::crypto::daemon::provider::crypto_executor
{

/// Groups the stable per-context parameters for KeyManagementExecutor operations.
///
/// These values are set once during InitializeContext() and remain constant for
/// the lifetime of the handler context.  Passing them as a struct reduces the
/// executor's Execute() call from 5 parameters to 3 (context, operationId, request).
struct KeyMgmtExecutionContext
{
    common::ProviderId provider_id{common::kInvalidProviderId};
    std::uint64_t client_id{0U};
    std::uint64_t context_node_id{0U};
};

}  // namespace score::crypto::daemon::provider::crypto_executor

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_EXECUTORS_KEY_MGMT_CONTEXT_HPP

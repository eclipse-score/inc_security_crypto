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

#ifndef SCORE_CRYPTO_DAEMON_COMMON_OPERATION_ACTORS_HPP
#define SCORE_CRYPTO_DAEMON_COMMON_OPERATION_ACTORS_HPP

#include <limits>

#include "score/crypto/daemon/common/types.hpp"

namespace score::crypto::daemon::common::actors
{

inline constexpr OperationActor OP_ACTOR_CONTROL = 1;
inline constexpr OperationActor OP_ACTOR_MEDIATOR = 2;
inline constexpr OperationActor OP_ACTOR_PROVIDER = 3;
inline constexpr OperationActor OP_ACTOR_HASH_HANDLER = 4;
inline constexpr OperationActor OP_ACTOR_KEY_MANAGEMENT = 5;
inline constexpr OperationActor OP_ACTOR_MAC_HANDLER = 6;

// Starting point for custom actors
inline constexpr OperationActor CUSTOM_ACTOR_START = 1 << (std::numeric_limits<OperationActor>::digits - 1);

}  // namespace score::crypto::daemon::common::actors

#endif  // SCORE_CRYPTO_DAEMON_COMMON_OPERATION_ACTORS_HPP

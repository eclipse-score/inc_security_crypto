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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_HANDLER_OPERATIONS_STREAM_OPERATION_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_HANDLER_OPERATIONS_STREAM_OPERATION_HPP

#include <cstdint>

namespace score::crypto::daemon::provider::handler
{

/// @brief Streaming operation kind used to drive the stream state machine.
///
/// Each handler's operations header maps its own INIT / UPDATE / FINALIZE
/// actions onto these values with a ToStreamOperation() function, so the state
/// machine never depends on the numeric value an action happens to carry.
enum class StreamOperation : std::uint8_t
{
    kInit,      ///< Initialize (or restart) a streaming operation.
    kUpdate,    ///< Feed additional data into an active stream.
    kFinalize,  ///< Complete the stream and produce the final result.
};

}  // namespace score::crypto::daemon::provider::handler

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_HANDLER_OPERATIONS_STREAM_OPERATION_HPP

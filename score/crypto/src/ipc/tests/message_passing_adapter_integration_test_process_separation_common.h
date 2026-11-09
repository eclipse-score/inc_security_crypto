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

#ifndef SCORE_CRYPTO_IPC_MESSAGE_PASSING_PROCESS_TEST_CONTRACT_H
#define SCORE_CRYPTO_IPC_MESSAGE_PASSING_PROCESS_TEST_CONTRACT_H

#include "score/crypto/src/daemon/control_plane/control_protocol.h"

#include <cstdint>
#include <string_view>

namespace score::crypto::ipc::message_passing::process_test
{

namespace protocol = score::crypto::daemon::control_plane::protocol;

inline constexpr std::string_view kServiceIdentifier{"crypto_adapter_process_separation"};
inline constexpr protocol::OperationIdentifier kEchoOperationId{17U, 3U};
inline constexpr std::uint64_t kEchoValue{0xA1B2C3D4E5F60718ULL};
inline constexpr std::uint64_t kLongRunningOperationValue{0xF1E2D3C4B5A69788ULL};

}  // namespace score::crypto::ipc::message_passing::process_test

#endif  // SCORE_CRYPTO_IPC_MESSAGE_PASSING_PROCESS_TEST_CONTRACT_H

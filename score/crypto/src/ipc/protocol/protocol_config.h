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

#ifndef SCORE_CRYPTO_IPC_PROTOCOL_CONFIG_H
#define SCORE_CRYPTO_IPC_PROTOCOL_CONFIG_H

#include <cstdint>

namespace score::crypto::ipc::protocol_config
{

/// @brief Maximum serialized control message size in bytes.
/// @details Must not exceed the payload limit of the transport.
/// @note This is currently limited by a limit imposed by the underlying score message_passing implementation
// See: score/crypto/src/ipc/message_passing_adapter/ipc_config.h
inline constexpr std::uint16_t kMaxSerializedBytes = 2U * 1024U;

}  // namespace score::crypto::ipc::protocol_config

#endif  // SCORE_CRYPTO_IPC_PROTOCOL_CONFIG_H

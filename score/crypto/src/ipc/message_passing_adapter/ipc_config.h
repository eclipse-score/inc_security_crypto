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

#ifndef SCORE_CRYPTO_IPC_MESSAGE_PASSING_ADAPTER_IPC_CONFIG_H
#define SCORE_CRYPTO_IPC_MESSAGE_PASSING_ADAPTER_IPC_CONFIG_H

#include "score/crypto/src/daemon/config/inc/config.hpp"
#include "score/crypto/src/ipc/protocol/protocol_config.h"

#include <chrono>
#include <cstdint>
#include <string_view>
#include <type_traits>

namespace score::crypto::ipc
{

/// @brief Prefix identifying score IPC connection endpoints.
constexpr std::string_view kScoreConnectionEndpointPrefix = "score://";

/// @brief Default shared control endpoint identifier.
/// @details Linux uses an abstract Unix-domain socket; QNX maps it below /mw_com/message_passing/.
constexpr std::string_view kControlServiceIdentifier = score::crypto::daemon::config::IPCConfig::kDefaultEndpoint;

/// @brief Maximum number of concurrently reserved client connections.
inline constexpr std::uint32_t kMaxTotalConnections = 128U;
static_assert(kMaxTotalConnections > 0U, "There must be at least one total connection allowed");

/// @brief Maximum reserved connections for one UID,
/// Effective limit is also bounded by kMaxTotalConnections.
inline constexpr std::uint32_t kMaxConnectionsPerUid = kMaxTotalConnections;
static_assert(kMaxConnectionsPerUid > 0U, "A UID must be allowed to open at least one connection");
static_assert(kMaxConnectionsPerUid <= kMaxTotalConnections,
              "The per-UID connection limit cannot exceed global capacity");

/// @brief Maximum outstanding operations admitted for one connection.
/// @details Bounds the client send storage and server notification storage requirements.
/// @note A connection will only be freed, after the server side cleanup has completed.
// This may temporarily reduce the number of available connections.
// In case the cleanup fails, the connection will remain occupied.
inline constexpr std::uint32_t kMaxOutstandingOperationsPerConnection = 31U;
/// @brief Number of client sends reserved for outstanding operations on one connection.
inline constexpr std::uint32_t kClientQueuedSendCapacity = kMaxOutstandingOperationsPerConnection;

/// @brief Number of queued server notifications reserved for one connection.
inline constexpr std::uint32_t kServerNotificationCapacityPerConnection = kMaxOutstandingOperationsPerConnection;

static_assert(kServerNotificationCapacityPerConnection == kMaxOutstandingOperationsPerConnection,
              "The client storage capacity must match the queued-send allocation ");
static_assert(kMaxOutstandingOperationsPerConnection <= kServerNotificationCapacityPerConnection,
              "The per-connection operation limit must leave notification capacity available");

/// @brief Maximum serialized IPC payload size in bytes.
inline constexpr std::uint16_t kMaxPayloadBytes = protocol_config::kMaxSerializedBytes;

// IPC should be able to transfer the full protocol buffer
static_assert(kMaxPayloadBytes >= protocol_config::kMaxSerializedBytes,
              "IPC must be able to transfer the full protocol buffer");

// score communication message passing under QNX currently has a limit of 2088 Bytes
// See: https://github.com/eclipse-score/communication/issues/848
static_assert(kMaxPayloadBytes <= 2088U, "Payload size exceeds QNX message passing limit");

static_assert(std::is_same_v<decltype(kMaxPayloadBytes), const std::uint16_t>, "MW COM uses uint16_t for payload size");

/// @brief Additional client wait time for a terminal response after the daemon-side timeout.
/// @details The requested timeout is used and sent to the daemon, however the client does also enforce
/// a maximum timeout.
/// In order to increase the chance, that we get a proper response from the daemon a small grace
/// period is added on the client side. This allows transfer of response from the daemon ad thus
/// can help in identifying on the client side, if the request was executed or not.
/// If no response is received within the requested timeout plus the grace period,
/// the client unblocks in order to guarantee bounded-call times.
inline constexpr std::chrono::milliseconds kTimeoutGracePeriod = std::chrono::milliseconds{5U};

/// @brief Maximum request timeout enforced by the client, including requests asking for infinity.
/// @note The client will wait kMaximumRequestTimeout + kTimeoutGracePeriod
inline constexpr std::chrono::milliseconds kMaximumRequestTimeout = std::chrono::milliseconds{600000U};

/// @brief Number of server worker threads for request and cleanup jobs.
inline constexpr std::uint32_t kWorkerThreads = 32U;
static_assert(kWorkerThreads > 0U, "The server must have at least one worker thread");

/// @brief Capacity for queued cleanup jobs, should be sufficient for every admitted client identity.
inline constexpr std::uint32_t kCleanupQueueCapacity = kMaxTotalConnections;
static_assert(kCleanupQueueCapacity >= kMaxTotalConnections,
              "The cleanup queue must hold one job for every admitted client identity");

}  // namespace score::crypto::ipc

#endif  // SCORE_CRYPTO_IPC_MESSAGE_PASSING_ADAPTER_IPC_CONFIG_H

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

#include "score/crypto/src/ipc/protocol/protocol_config.h"

#include <chrono>
#include <cstdint>
#include <string_view>
#include <type_traits>

namespace score::crypto::ipc
{

// Endpoint schema identifier prefix for score IPC connections using message passing transport
constexpr std::string_view kScoreConnectionEndpointPrefix = "score://";

// Shared control endpoint identifier. On Linux, the message-passing transport uses this as an
// abstract Unix-domain socket name, so no filesystem socket is created. On QNX, the dispatch
// transport maps the identifier below /mw_com/message_passing/.
constexpr std::string_view kControlServiceIdentifier = "crypto_daemon.sock";

// Total maximum of concurrently active connections
inline constexpr std::uint32_t kMaxTotalConnections = 128U;
static_assert(kMaxTotalConnections > 0U, "There must be at least one total connection allowed");

// Maximum number of connections allowed per user ID.
// kMaxTotalConnections does still apply as upper limit.
inline constexpr std::uint32_t kMaxConnectionsPerUid = kMaxTotalConnections;
static_assert(kMaxConnectionsPerUid > 0U, "A UID must be allowed to open at least one connection");
static_assert(kMaxConnectionsPerUid <= kMaxTotalConnections,
              "The per-UID connection limit cannot exceed global capacity");

// Hint: A connection will only be freed, after the server side cleanup is completed.
// This may temporarily reduce the number of available connections.
// In case the cleanup fails, the connection will remain occupied.

// In order to ensure, that the server can send notifications for all outstanding operations,
// the number of outstanding operations per connection must be limited.
// This does also defines the buffer requirements for the client and server-side
inline constexpr std::uint32_t kMaxOutstandingOperationsPerConnection = 31U;
// Reserve one additional slot for a cancellation message while all operation slots are occupied.
// No need for an additional Notification slot on server-side, since cancellation is fire-and-forget
inline constexpr std::uint32_t kClientAdditionalCancelCapacity = 1U;
inline constexpr std::uint32_t kClientQueuedSendCapacity =
    kMaxOutstandingOperationsPerConnection + kClientAdditionalCancelCapacity;

// No need for additional slot for the cancellation on the server side, since cancellation is fire-and-forget
inline constexpr std::uint32_t kServerNotificationCapacityPerConnection = kMaxOutstandingOperationsPerConnection;

static_assert(kServerNotificationCapacityPerConnection == kMaxOutstandingOperationsPerConnection,
              "The client storage capacity must match the queued-send allocation ");
static_assert(kMaxOutstandingOperationsPerConnection <= kServerNotificationCapacityPerConnection,
              "The per-connection operation limit must leave notification capacity available");

// Define the maximum payload size for IPC communication (in serialized bytes)
inline constexpr std::uint16_t kMaxPayloadBytes = protocol_config::kMaxSerializedBytes;

// IPC should be able to transfer the full protocol buffer
static_assert(kMaxPayloadBytes >= protocol_config::kMaxSerializedBytes,
              "IPC must be able to transfer the full protocol buffer");

// score communication message passing under QNX currently has a limit of 2088 Bytes
// See: https://github.com/eclipse-score/communication/issues/848
static_assert(kMaxPayloadBytes <= 2088U, "Payload size exceeds QNX message passing limit");

static_assert(std::is_same_v<decltype(kMaxPayloadBytes), const std::uint16_t>, "MW COM uses uint16_t for payload size");

// The requested timeout is used and sent to the daemon, however the client does also enforce
// a maximum timeout.
// In order to increase the chance, that we get a proper response from the daemon a small grace
// period is added on the client side. This allows transfer of response from the daemon ad thus
// can help in identifying on the client side, if the request was executed or not.
// If no response is received within the requested timeout plus the grace period,
// the client unblocks in order to guarantee bounded-call times.
inline constexpr std::chrono::milliseconds kTimeoutGracePeriod = std::chrono::milliseconds{5U};

// The maximum allowed request timeout on the client side.
// Even in case an infinite timeout is specified, it is clamped to this value.
// Hint: The client will wait kMaximumRequestTimeout + kTimeoutGracePeriod
inline constexpr std::chrono::milliseconds kMaximumRequestTimeout = std::chrono::milliseconds{600000U};

// Number of worker threads for handling server-side tasks.
inline constexpr std::uint32_t kWorkerThreads = 32U;
static_assert(kWorkerThreads > 0U, "The server must have at least one worker thread");

// Each connection may trigger a cleanup job, which is queued in for completion.
// The cleanup queue must have enough capacity to hold one job for every admitted client identity.
inline constexpr std::uint32_t kCleanupQueueCapacity = kMaxTotalConnections;
static_assert(kCleanupQueueCapacity >= kMaxTotalConnections,
              "The cleanup queue must hold one job for every admitted client identity");

}  // namespace score::crypto::ipc

#endif  // SCORE_CRYPTO_IPC_MESSAGE_PASSING_ADAPTER_IPC_CONFIG_H

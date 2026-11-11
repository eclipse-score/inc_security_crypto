/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

#ifndef SCORE_CRYPTO_IPC_MESSAGE_PASSING_WORK_ITEM_H
#define SCORE_CRYPTO_IPC_MESSAGE_PASSING_WORK_ITEM_H

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"

#include <score/span.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <variant>
#include <vector>

namespace score::crypto::ipc::protocol
{
class IControlCodec;
}  // namespace score::crypto::ipc::protocol

namespace score::crypto::ipc::message_passing::detail
{

namespace protocol = daemon::control_plane::protocol;

class Session;

enum class WorkItemState : std::uint8_t
{
    kQueued,           ///< Admitted and waiting to execute.
    kRunning,          ///< Being processed by a worker.
    kDeadlineExpired,  ///< Its deadline passed before execution began.
    kCompleted,        ///< Reached a terminal response or error path.
};

/**
 * @brief
 * Owns the server-side state and backing bytes for one received request.
 * Tracks request identity and deadline from admission through completion.
 * @endrst
 */
struct WorkItem final
{
    /// @brief Creates an owned work item from serialized request bytes.
    /// @param serialized_request Request bytes to copy into item-owned storage.
    /// @param session Session that admitted the request.
    /// @param codec Codec used to inspect request metadata.
    /// @param received_at Time the server received the request.
    /// @return The work item, or an error if validation or allocation fails.
    static score::crypto::Expected<std::shared_ptr<WorkItem>, score::crypto::daemon::common::DaemonErrorCode> Create(
        score::cpp::span<const std::uint8_t> serialized_request,
        const std::shared_ptr<Session>& session,
        const score::crypto::ipc::protocol::IControlCodec& codec,
        std::chrono::steady_clock::time_point received_at) noexcept;

    /// @brief Fully decodes the owned request bytes.
    /// @param codec Codec used to decode the request.
    /// @return Success, or an error if decoding fails.
    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> DeserializeRequest(
        const score::crypto::ipc::protocol::IControlCodec& codec) noexcept;

    /// @brief Moves a queued item to running or marks it expired.
    /// @return The resulting work-item state.
    WorkItemState PrepareForExecution() noexcept;

    /// @brief Marks the item complete and notifies its session.
    void Complete() noexcept;

    /// @brief Returns this item's request ID.
    /// @return The protocol request identifier.
    protocol::RequestId GetRequestId() const noexcept;

    /// @brief Returns the client ID assigned to the owning session.
    /// @return The server-assigned client identifier.
    protocol::ClientId GetClientId() const noexcept;

    /// @brief Returns the decoded request for handler processing.
    /// @return Mutable reference to the owned request.
    protocol::ControlRequest& GetRequest() noexcept;

  private:
    friend class Session;

    mutable std::mutex m_mutex{};
    std::weak_ptr<Session> m_session{};
    WorkItemState m_lifecycle{WorkItemState::kQueued};
    // Owns the backing storage for all string and buffer views in request.
    std::vector<std::uint8_t> serialized_request{};
    protocol::ControlRequest request{};

    // Additionally store these elements, such that we can easily access them within the IPC
    // classes, without the need to fully deserialize the request.
    // We also need to capture the deadline and clientId here to overwrite then after deserialization.
    protocol::RequestId request_id{0U};
    protocol::ClientId client_id{0U};
    std::chrono::steady_clock::time_point deadline{};
    protocol::ExecutionPolicy execution_policy{};
};

}  // namespace score::crypto::ipc::message_passing::detail

#endif  // SCORE_CRYPTO_IPC_MESSAGE_PASSING_WORK_ITEM_H

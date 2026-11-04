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

#include "score/crypto/src/ipc/message_passing_adapter/client/client_session/pending_call_registry.h"

#include "score/crypto/src/ipc/message_passing_adapter/ipc_config.h"

#include "score/mw/log/logging.h"

#include <sys/types.h>
#include <unistd.h>
#include <new>
#include <utility>

namespace score::crypto::ipc::message_passing
{

PendingCallRegistry::PendingCallRegistry() = default;

score::crypto::Expected<PendingCallRegistry::RegisteredPendingCall, score::crypto::CryptoErrorCode>
PendingCallRegistry::Register() noexcept
{
    using RequestId = daemon::control_plane::protocol::RequestId;

    std::lock_guard<std::mutex> lock(pending_calls_mutex_);
    if (pending_calls_.size() >= ipc::kMaxOutstandingOperationsPerConnection)
    {
        return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kProviderBusy);
    }

    PendingCallHandle call;
    try
    {
        call = std::make_shared<PendingCall>();
    }
    catch (const std::bad_alloc&)
    {
        score::mw::log::LogError() << "[IPC][MESSAGE_PASSING_CLIENT] Allocation failed while creating pending call";
        return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kAllocationFailed);
    }
    catch (...)
    {
        score::mw::log::LogError() << "[IPC][MESSAGE_PASSING_CLIENT] Unexpected failure while creating pending call";
        return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInternalError);
    }

    const auto request_id_result = GenerateRequestId(lock);
    if (!request_id_result.has_value())
    {
        score::mw::log::LogError() << "[IPC][MESSAGE_PASSING_CLIENT] Failed to generate a unique pending request ID";
        return score::crypto::make_unexpected(request_id_result.error());
    }

    try
    {
        const auto request_id = request_id_result.value();
        const auto inserted = pending_calls_.emplace(request_id, call).second;
        if (!inserted)
        {
            score::mw::log::LogError() << "[IPC][MESSAGE_PASSING_CLIENT] Duplicate pending request_id=" << request_id;
            return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInternalError);
        }
        return RegisteredPendingCall{request_id, std::move(call)};
    }
    catch (const std::bad_alloc&)
    {
        score::mw::log::LogError() << "[IPC][MESSAGE_PASSING_CLIENT] Allocation failed while registering request_id="
                                   << request_id_result.value();
        return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kAllocationFailed);
    }
    catch (...)
    {
        score::mw::log::LogError() << "[IPC][MESSAGE_PASSING_CLIENT] Unexpected failure while registering request_id="
                                   << request_id_result.value();
        return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInternalError);
    }
}

score::crypto::Expected<daemon::control_plane::protocol::RequestId, score::crypto::CryptoErrorCode>
PendingCallRegistry::GenerateRequestId(const std::lock_guard<std::mutex>& lock)
{
    static_cast<void>(lock);
    const auto process_id = static_cast<daemon::control_plane::protocol::RequestId>(::getpid());
    const auto process_prefix = process_id << 32U;
    for (std::uint32_t attempt{0U}; attempt < ipc::kMaxOutstandingOperationsPerConnection; ++attempt)
    {
        const auto sequence = next_request_counter_++;
        if (next_request_counter_ == 0U)
        {
            next_request_counter_ = 1U;
        }
        const auto request_id = process_prefix | sequence;
        if ((request_id != 0U) && (pending_calls_.find(request_id) == pending_calls_.end()))
        {
            return request_id;
        }
    }
    score::mw::log::LogError() << "[IPC][MESSAGE_PASSING_CLIENT] Exhausted attempts to generate a unique request ID";
    return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInternalError);
}

void PendingCallRegistry::Complete(const daemon::control_plane::protocol::RequestId request_id,
                                   daemon::control_plane::protocol::ControlResponse response) noexcept
{
    std::lock_guard<std::mutex> lock(pending_calls_mutex_);
    const auto iterator = pending_calls_.find(request_id);
    if (iterator == pending_calls_.end())
    {
        score::mw::log::LogWarn() << "[IPC][MESSAGE_PASSING_CLIENT] Dropped late terminal notification for request_id="
                                  << request_id;
        return;
    }

    iterator->second->Complete(std::move(response));
    pending_calls_.erase(iterator);
}

void PendingCallRegistry::Fail(const daemon::control_plane::protocol::RequestId request_id,
                               const PendingCallHandle& expected_call,
                               const score::crypto::CryptoErrorCode error) noexcept
{
    std::lock_guard<std::mutex> lock(pending_calls_mutex_);
    const auto iterator = pending_calls_.find(request_id);
    if (iterator == pending_calls_.end())
    {
        score::mw::log::LogWarn() << "[IPC][MESSAGE_PASSING_CLIENT] Pending call was already removed for request_id="
                                  << request_id;
        return;
    }
    if (iterator->second != expected_call)
    {
        score::mw::log::LogError() << "[IPC][MESSAGE_PASSING_CLIENT] Pending call handle mismatch for request_id="
                                   << request_id;
        return;
    }
    iterator->second->Fail(error);
    pending_calls_.erase(iterator);
}

score::crypto::Expected<daemon::control_plane::protocol::ControlResponse, score::crypto::CryptoErrorCode>
PendingCallRegistry::WaitForResponse(const daemon::control_plane::protocol::RequestId request_id,
                                     const PendingCallHandle& call,
                                     const std::chrono::steady_clock::time_point deadline) noexcept
{
    if (call == nullptr)
    {
        score::mw::log::LogError() << "[IPC][MESSAGE_PASSING_CLIENT] Cannot wait for a null pending call";
        return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInternalError);
    }
    auto result = call->WaitForResponse(deadline);
    if (!result.has_value() && (result.error() == score::crypto::CryptoErrorCode::kOperationResponseTimedOut))
    {
        static_cast<void>(Fail(request_id, call, score::crypto::CryptoErrorCode::kOperationResponseTimedOut));
        result = call->WaitForResponse(std::chrono::steady_clock::now());
        if (!result.has_value() && (result.error() == score::crypto::CryptoErrorCode::kOperationResponseTimedOut))
        {
            score::mw::log::LogWarn() << "[IPC][MESSAGE_PASSING_CLIENT] Timed out waiting for response to request_id="
                                      << request_id;
        }
    }
    return result;
}

void PendingCallRegistry::FailAllPendingCalls(const score::crypto::CryptoErrorCode error) noexcept
{
    std::lock_guard<std::mutex> lock(pending_calls_mutex_);
    for (auto iterator = pending_calls_.begin(); iterator != pending_calls_.end();)
    {
        static_cast<void>(iterator->second->Fail(error));
        iterator = pending_calls_.erase(iterator);
    }
}

}  // namespace score::crypto::ipc::message_passing

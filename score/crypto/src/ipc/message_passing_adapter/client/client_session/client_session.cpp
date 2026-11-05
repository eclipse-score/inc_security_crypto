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

#include "score/crypto/src/ipc/message_passing_adapter/client/client_session/client_session.h"

#include "score/crypto/src/ipc/message_passing_adapter/ipc_config.h"
#include "score/mw/log/logging.h"

#include <algorithm>
#include <memory>
#include <new>
#include <utility>

namespace score::crypto::ipc::message_passing
{
namespace
{
namespace protocol = daemon::control_plane::protocol;

std::chrono::milliseconds ClampRequestTimeout(const std::chrono::milliseconds timeout) noexcept
{
    return std::min(timeout, ipc::kMaximumRequestTimeout);
}

}  // namespace

ClientSession::ClientSession(const score::crypto::ipc::protocol::IControlCodec& codec,
                             score::cpp::pmr::unique_ptr<score::message_passing::IClientConnection> connection)
    : codec_(codec), connection_(std::move(connection))
{
}

ClientSession::~ClientSession() noexcept
{
    Shutdown();
}

score::crypto::Expected<protocol::ControlResponse, score::crypto::CryptoErrorCode> ClientSession::SendRequest(
    protocol::ControlRequest& request) noexcept
{
    return SendRequest(request, ipc::kMaximumRequestTimeout, {});
}

score::crypto::Expected<protocol::ControlResponse, score::crypto::CryptoErrorCode> ClientSession::SendRequest(
    protocol::ControlRequest& request,
    const std::chrono::milliseconds timeout,
    const daemon::control_plane::CancellationToken& cancellation) noexcept
{
    const auto now = std::chrono::steady_clock::now();
    const auto deadline = now + ClampRequestTimeout(timeout);

    const auto ready_result = WaitForConnectionReady(deadline);
    if (!ready_result.has_value())
    {
        return score::crypto::make_unexpected(ready_result.error());
    }

    if (cancellation.IsCancellationRequested())
    {
        return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kOperationCancelled);
    }

    const auto remaining_timeout =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
    if (remaining_timeout <= std::chrono::milliseconds::zero())
    {
        return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kOperationTimedOut);
    }

    auto registration_result = pending_call_registry_.Register();
    if (!registration_result.has_value())
    {
        return score::crypto::make_unexpected(registration_result.error());
    }
    auto [request_id, call] = std::move(*registration_result);
    request.request_id = request_id;
    request.deadline = deadline;

    const auto serialized = codec_.SerializeRequest(request);
    if (!serialized.has_value())
    {
        pending_call_registry_.Fail(request_id, call, serialized.error());
        return score::crypto::make_unexpected(serialized.error());
    }

    const auto bytes = std::move(serialized).value();
    if (bytes.size() > ipc::kMaxPayloadBytes)
    {
        pending_call_registry_.Fail(request_id, call, score::crypto::CryptoErrorCode::kInvalidArgument);
        return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInvalidArgument);
    }

    const auto send_result = TransferRequestBytes(score::cpp::span<const std::uint8_t>{bytes.data(), bytes.size()});
    if (!send_result.has_value())
    {
        pending_call_registry_.Fail(request_id, call, send_result.error());
        return score::crypto::make_unexpected(send_result.error());
    }

    daemon::control_plane::CancellationRegistration cancellation_registration;
    // Cancellation callback registration can allocate its type-erased callback and extend token storage.
    try
    {
        cancellation_registration = cancellation.RegisterCallback([this, request_id]() noexcept {
            if (!CreateAndSendCancelRequest(request_id))
            {
                score::mw::log::LogWarn()
                    << "[IPC][MESSAGE_PASSING_CLIENT] Failed to send cancellation request for request_id=" << request_id
                    << "; waiting for terminal response or request timeout";
            }
        });
    }
    catch (...)
    {
        score::mw::log::LogWarn()
            << "[IPC][MESSAGE_PASSING_CLIENT] Failed to register cancellation callback for request_id=" << request_id
            << "; waiting for terminal response or request timeout";
    }

    auto response = pending_call_registry_.WaitForResponse(request_id, call, deadline + ipc::kTimeoutGracePeriod);
    cancellation_registration.DeregisterAndWait();
    return response;
}

score::crypto::Expected<std::monostate, score::crypto::CryptoErrorCode> ClientSession::WaitForConnectionReady(
    const std::chrono::steady_clock::time_point deadline) noexcept
{
    std::unique_lock<std::mutex> lock(mutex_);
    state_condition_.wait_until(lock, deadline, [this] {
        return (state_ == LifecycleState::kReady) || (state_ == LifecycleState::kStopping) ||
               (state_ == LifecycleState::kStopped);
    });

    if (state_ == LifecycleState::kReady)
    {
        return {};
    }

    if (state_ == LifecycleState::kStopped || state_ == LifecycleState::kStopping)
    {
        auto stop_reason = connection_->GetStopReason();
        if (stop_reason == score::message_passing::IClientConnection::StopReason::kPermission)
        {
            score::mw::log::LogError() << "ClientSession::WaitForConnectionReady failed due to access denied.";
            return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kAccessDenied);
        }
        score::mw::log::LogError() << "ClientSession::WaitForConnectionReady failed due to stop reason: "
                                   << static_cast<int>(stop_reason);
        return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kConnectionFailed);
    }

    score::mw::log::LogError() << "ClientSession::WaitForConnectionReady timed out before connection became ready.";
    return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kConnectionFailed);
}

score::crypto::Expected<std::monostate, score::crypto::CryptoErrorCode> ClientSession::TransferRequestBytes(
    const score::cpp::span<const std::uint8_t> bytes) noexcept
{
    const std::lock_guard<std::mutex> state_lock(mutex_);
    if (state_ != LifecycleState::kReady)
    {
        score::mw::log::LogError() << "ClientSession::TransferRequestBytes called while connection is not ready.";
        return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kConnectionFailed);
    }

    const auto send_result = connection_->Send(bytes);
    if (!send_result.has_value())
    {
        score::mw::log::LogError() << "ClientSession::TransferRequestBytes failed to send bytes.";
        return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kConnectionFailed);
    }

    return {};
}

void ClientSession::HandleTransportState(const LifecycleState state) noexcept
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        state_ = state;
    }
    state_condition_.notify_all();
}

score::crypto::Expected<std::monostate, score::crypto::CryptoErrorCode> ClientSession::StartCallbacks() noexcept
{
    try
    {
        connection_->Start(
            [this](const score::message_passing::IClientConnection::State state) noexcept {
                OnTransportStateChanged(state);
            },
            [this](const score::cpp::span<const std::uint8_t> message) noexcept {
                OnResponseBytes(message);
            });
        return {};
    }
    catch (const std::bad_alloc&)
    {
        score::mw::log::LogError()
            << "[IPC][MESSAGE_PASSING_CLIENT] Allocation failed while starting connection callbacks";
        return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kAllocationFailed);
    }
    catch (...)
    {
        score::mw::log::LogError() << "[IPC][MESSAGE_PASSING_CLIENT] Failed to start connection callbacks";
        return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kConnectionFailed);
    }
}

void ClientSession::OnTransportStateChanged(const score::message_passing::IClientConnection::State state) noexcept
{
    switch (state)
    {
        case score::message_passing::IClientConnection::State::kStarting:
        {
            HandleTransportState(LifecycleState::kStarting);
            break;
        }
        case score::message_passing::IClientConnection::State::kReady:
        {
            HandleTransportState(LifecycleState::kReady);
            break;
        }
        case score::message_passing::IClientConnection::State::kStopping:
        {
            HandleTransportState(LifecycleState::kStopping);
            FailAllPendingCalls(score::crypto::CryptoErrorCode::kConnectionFailed);
            break;
        }
        case score::message_passing::IClientConnection::State::kStopped:
        {
            HandleTransportState(LifecycleState::kStopped);
            FailAllPendingCalls(score::crypto::CryptoErrorCode::kConnectionFailed);
            break;
        }
        default:
        {
            score::mw::log::LogError() << "[IPC][MESSAGE_PASSING_CLIENT] Received unknown transport state="
                                       << static_cast<int>(state);
            HandleTransportState(LifecycleState::kStopped);
            FailAllPendingCalls(score::crypto::CryptoErrorCode::kConnectionFailed);
        }
    }
}

void ClientSession::OnResponseBytes(const score::cpp::span<const std::uint8_t> message) noexcept
{
    protocol::ControlResponse response{};
    const auto deserialize_result = codec_.DeserializeResponse(message, response);
    if (!deserialize_result.has_value())
    {
        const auto error = deserialize_result.error();
        score::mw::log::LogError() << "[IPC][MESSAGE_PASSING_CLIENT] Dropped malformed response notification (size="
                                   << message.size() << ", error=" << static_cast<int>(error) << ")";
        pending_call_registry_.FailAllPendingCalls(error);
        return;
    }
    const auto request_id = response.request_id;
    pending_call_registry_.Complete(request_id, std::move(response));
}

void ClientSession::Shutdown() noexcept
{
    FailAllPendingCalls(score::crypto::CryptoErrorCode::kConnectionFailed);
    connection_->Stop();
    WaitForStopped();
}

void ClientSession::FailAllPendingCalls(const score::crypto::CryptoErrorCode error) noexcept
{
    pending_call_registry_.FailAllPendingCalls(error);
}

void ClientSession::WaitForStopped() noexcept
{
    std::unique_lock<std::mutex> lock(mutex_);
    state_condition_.wait(lock, [this] {
        return state_ == LifecycleState::kStopped;
    });
}

bool ClientSession::CreateAndSendCancelRequest(const protocol::RequestId request_id) noexcept
{
    protocol::ControlRequest cancellation{};
    cancellation.request_id = request_id;
    cancellation.kind = protocol::ControlRequestKind::kCancel;
    cancellation.deadline = std::chrono::steady_clock::now() + ipc::kMaximumRequestTimeout;

    const auto serialized = codec_.SerializeRequest(cancellation);
    if (!serialized.has_value())
    {
        return false;
    }
    const auto bytes = std::move(serialized).value();
    if (bytes.size() > ipc::kMaxPayloadBytes)
    {
        return false;
    }
    return TransferRequestBytes(score::cpp::span<const std::uint8_t>{bytes.data(), bytes.size()}).has_value();
}

}  // namespace score::crypto::ipc::message_passing

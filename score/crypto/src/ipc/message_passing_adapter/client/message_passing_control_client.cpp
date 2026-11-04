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

#include "score/crypto/src/ipc/message_passing_adapter/client/message_passing_control_client.h"

#include "score/crypto/src/ipc/message_passing_adapter/ipc_config.h"
#include "score/message_passing/client_factory.h"
#include "score/message_passing/i_client_connection.h"
#include "score/message_passing/i_client_factory.h"
#include "score/message_passing/service_protocol_config.h"
#include "score/mw/log/logging.h"

#include <score/expected.hpp>
#include <score/memory.hpp>
#include <score/span.hpp>

#include <chrono>
#include <cstdint>
#include <new>
#include <string_view>

namespace score::crypto::ipc::message_passing
{
namespace
{
namespace protocol = daemon::control_plane::protocol;

score::message_passing::IClientFactory::ClientConfig BuildClientConfig() noexcept
{
    score::message_passing::IClientFactory::ClientConfig config{};
    config.max_async_replies = 0U;
    config.max_queued_sends = ipc::kClientQueuedSendCapacity;
    config.fully_ordered = false;
    config.truly_async = true;
    config.sync_first_connect = false;
    return config;
}

score::cpp::pmr::unique_ptr<score::message_passing::IClientConnection> CreateConnection(
    score::message_passing::ClientFactory& factory,
    const std::string_view service_identifier)
{
    const score::message_passing::ServiceProtocolConfig protocol_config{
        service_identifier,
        ipc::kMaxPayloadBytes,
        ipc::kMaxPayloadBytes,
        ipc::kMaxPayloadBytes,
    };
    return factory.Create(protocol_config, BuildClientConfig());
}

}  // namespace

MessagePassingControlClient::MessagePassingControlClient(
    std::unique_ptr<score::message_passing::ClientFactory> factory,
    score::cpp::pmr::unique_ptr<score::message_passing::IClientConnection> connection)
    : factory_{std::move(factory)}, codec_{}, session_{codec_, std::move(connection)}
{
}

Expected<std::shared_ptr<MessagePassingControlClient>, score::crypto::CryptoErrorCode>
MessagePassingControlClient::Create(const std::string_view service_identifier) noexcept
{
    std::shared_ptr<MessagePassingControlClient> client;
    try
    {
        auto factory = std::make_unique<score::message_passing::ClientFactory>();
        auto connection = CreateConnection(*factory, service_identifier);
        if (connection == nullptr)
        {
            score::mw::log::LogError()
                << "[IPC][MESSAGE_PASSING_CLIENT] Client factory returned no connection for service="
                << service_identifier;
            return make_unexpected(score::crypto::CryptoErrorCode::kConnectionFailed);
        }
        client = std::shared_ptr<MessagePassingControlClient>{
            new MessagePassingControlClient{std::move(factory), std::move(connection)}};
    }
    catch (const std::bad_alloc&)
    {
        score::mw::log::LogError()
            << "[IPC][MESSAGE_PASSING_CLIENT] Allocation failed while creating client for service="
            << service_identifier;
        return make_unexpected(score::crypto::CryptoErrorCode::kAllocationFailed);
    }
    catch (...)
    {
        score::mw::log::LogError()
            << "[IPC][MESSAGE_PASSING_CLIENT] Unexpected failure while creating client for service="
            << service_identifier;
        return make_unexpected(score::crypto::CryptoErrorCode::kInternalError);
    }
    const auto callback_result = client->session_.StartCallbacks();
    if (!callback_result.has_value())
    {
        return make_unexpected(callback_result.error());
    }
    return client;
}

MessagePassingControlClient::~MessagePassingControlClient() noexcept
{
    session_.Shutdown();
}

Expected<protocol::ControlResponse, score::crypto::CryptoErrorCode> MessagePassingControlClient::SendRequest(
    protocol::ControlRequest& request) noexcept
{
    return session_.SendRequest(request);
}

Expected<protocol::ControlResponse, score::crypto::CryptoErrorCode> MessagePassingControlClient::SendRequest(
    protocol::ControlRequest& request,
    const std::chrono::milliseconds timeout,
    const CancellationToken& cancellation) noexcept
{
    return session_.SendRequest(request, timeout, cancellation);
}

}  // namespace score::crypto::ipc::message_passing

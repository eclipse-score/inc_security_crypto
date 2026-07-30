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

#include "score/crypto/src/api/contexts/src/mac_context_impl.hpp"

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/common/types.hpp"

#include "score/crypto/src/api/control_plane/i_connection.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/mac_handler_operations.hpp"

#include "score/result/result.h"
#include "score/span.hpp"

#include "score/mw/log/logging.h"
#include <algorithm>
#include <cstdint>
#include <cstring>

#include <memory>
#include <optional>
#include <utility>
#include <variant>

namespace score
{

namespace crypto
{

namespace proto = ::score::crypto::daemon::control_plane::protocol;
namespace actors = ::score::crypto::daemon::common::actors;
namespace mac_ops = ::score::crypto::daemon::provider::handler::mac_handler_operations;

MacContextImpl::MacContextImpl(std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
                               uint64_t context_id,
                               AlgorithmId algorithm,
                               std::shared_ptr<IBufferTranscoder> transcoder)
    : m_connection(std::move(connection)),
      m_context_id(context_id),
      m_algorithm(algorithm),
      m_transcoder(std::move(transcoder))
{
}

MacContextImpl::MacContextImpl(MacContextImpl&& other) noexcept
    : m_connection(std::move(other.m_connection)),
      m_context_id(std::exchange(other.m_context_id, 0)),
      m_algorithm(other.m_algorithm),
      m_transcoder(std::move(other.m_transcoder))
{
}

MacContextImpl& MacContextImpl::operator=(MacContextImpl&& other) noexcept
{
    if (this != &other)
    {
        CloseContext();
        m_connection = std::move(other.m_connection);
        m_context_id = std::exchange(other.m_context_id, 0);
        m_algorithm = other.m_algorithm;
        m_transcoder = std::move(other.m_transcoder);
    }
    return *this;
}

MacContextImpl::~MacContextImpl()
{
    CloseContext();
}

void MacContextImpl::CloseContext() noexcept
{
    if (m_context_id == 0)
    {
        return;
    }

    if (!m_connection)
    {
        score::mw::log::LogError() << "[API][MacContextImpl] ERROR: Connection is not initialized during destruction";
        return;
    }

    auto context_close_res = proto::ControlRequestBuilder()
                                 .forDataNodeId(m_context_id)
                                 .operation(score::crypto::daemon::mediator::operations::CloseContext())
                                 .build();

    if (!context_close_res.has_value())
    {
        score::mw::log::LogError()
            << "[API][MacContextImpl] ERROR: Failed to build CTX_CLOSE request during destruction";
        return;
    }

    auto response_res = m_connection->SendRequest(context_close_res.value());

    auto validator = proto::ControlResponseValidator::FromResult(response_res);
    validator.expectOperation(score::crypto::daemon::mediator::operations::CloseContext()).expectSuccess();

    if (!validator.isValid())
    {
        score::mw::log::LogError() << "[API][MacContextImpl] ERROR: CTX_CLOSE response validation failed: "
                                   << validator.getError();
        return;
    }
}

score::Result<std::monostate> MacContextImpl::Update(score::cpp::span<const uint8_t> data)
{
    proto::OperationRequestBuilder builder;
    builder.operation({actors::OP_ACTOR_MAC_HANDLER, mac_ops::MAC_UPDATE});

    auto tspan_result = m_transcoder->Acquire(data);
    if (!tspan_result.has_value())
    {
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(tspan_result.error(), "Failed to acquire input buffer")};
    }
    TranscoderSpan tspan = std::move(tspan_result.value());
    m_transcoder->AppendInputBuffer(builder, tspan);

    auto control_request_result = builder.build();
    if (!control_request_result.has_value())
    {
        score::mw::log::LogError() << "[API][MacContextImpl] ERROR: Failed to build MAC_UPDATE request";
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build MAC_UPDATE request")};
    }

    proto::ControlRequest control_req{};
    control_req.operation = control_request_result.value();
    control_req.data_node_id = m_context_id;
    auto control_response_res = m_connection->SendRequest(control_req);

    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation({actors::OP_ACTOR_MAC_HANDLER, mac_ops::MAC_UPDATE}).expectSuccess();

    if (!validator.isValid())
    {
        score::mw::log::LogError() << "[API][MacContextImpl] ERROR:" << validator.getError();
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "MAC_UPDATE daemon response invalid")};
    }

    return std::monostate{};
}

score::Result<std::size_t> MacContextImpl::Finalize(score::cpp::span<uint8_t> output)
{
    proto::OperationRequestBuilder builder;
    builder.operation({actors::OP_ACTOR_MAC_HANDLER, mac_ops::MAC_FINALIZE});

    auto tspan_result = m_transcoder->Acquire(output, /*is_output=*/true);
    if (!tspan_result.has_value())
    {
        return score::Result<std::size_t>{score::unexpect,
                                          MakeError(tspan_result.error(), "Failed to acquire output buffer")};
    }
    TranscoderSpan tspan = std::move(tspan_result.value());
    m_transcoder->AppendOutputBuffer(builder, tspan);

    auto control_request_result = builder.build();
    if (!control_request_result.has_value())
    {
        score::mw::log::LogError() << "[API][MacContextImpl] ERROR: Failed to build MAC_FINALIZE request";
        return score::Result<std::size_t>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build MAC_FINALIZE request")};
    }

    proto::ControlRequest control_req{};
    control_req.operation = control_request_result.value();
    control_req.data_node_id = m_context_id;
    auto control_response_res = m_connection->SendRequest(control_req);

    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation({actors::OP_ACTOR_MAC_HANDLER, mac_ops::MAC_FINALIZE}).expectSuccess();

    if (!validator.isValid())
    {
        score::mw::log::LogError() << "[API][MacContextImpl] ERROR:" << validator.getError();
        return score::Result<std::size_t>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "MAC_FINALIZE daemon response invalid")};
    }

    return m_transcoder->ExtractOutputBuffer(tspan, validator);
}

score::Result<bool> MacContextImpl::Verify(score::cpp::span<const uint8_t> mac)
{
    proto::OperationRequestBuilder builder;
    builder.operation({actors::OP_ACTOR_MAC_HANDLER, mac_ops::MAC_VERIFY});

    auto tspan_result = m_transcoder->Acquire(mac);
    if (!tspan_result.has_value())
    {
        return score::Result<bool>{score::unexpect, MakeError(tspan_result.error(), "Failed to acquire input buffer")};
    }
    TranscoderSpan tspan = std::move(tspan_result.value());
    m_transcoder->AppendInputBuffer(builder, tspan);

    auto control_request_result = builder.build();
    if (!control_request_result.has_value())
    {
        score::mw::log::LogError() << "[API][MacContextImpl] ERROR: Failed to build MAC_VERIFY request";
        return score::Result<bool>{score::unexpect,
                                   MakeError(CryptoErrorCode::kOperationFailed, "Failed to build MAC_VERIFY request")};
    }

    proto::ControlRequest control_req{};
    control_req.operation = control_request_result.value();
    control_req.data_node_id = m_context_id;
    auto control_response_res = m_connection->SendRequest(control_req);

    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation({actors::OP_ACTOR_MAC_HANDLER, mac_ops::MAC_VERIFY}).expectSuccess();

    if (!validator.isValid())
    {
        score::mw::log::LogError() << "[API][MacContextImpl] ERROR:" << validator.getError();
        return score::Result<bool>{score::unexpect,
                                   MakeError(CryptoErrorCode::kOperationFailed, "MAC_VERIFY daemon response invalid")};
    }

    auto verify_result = validator.getParameterAt<bool>(0, 0);
    if (!verify_result.has_value())
    {
        score::mw::log::LogError() << "[API][MacContextImpl] ERROR: MAC_VERIFY response has invalid parameter type";
        return score::Result<bool>{
            score::unexpect,
            MakeError(CryptoErrorCode::kOperationFailed, "MAC_VERIFY response has invalid parameter type")};
    }

    return verify_result.value();
}

score::Result<std::monostate> MacContextImpl::Reset()
{
    auto control_req_result = proto::ControlRequestBuilder()
                                  .forDataNodeId(m_context_id)
                                  .operation({actors::OP_ACTOR_MAC_HANDLER, mac_ops::MAC_RESET})
                                  .build();
    if (!control_req_result.has_value())
    {
        score::mw::log::LogError() << "[API][MacContextImpl] ERROR: Failed to build MAC_RESET request";
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build MAC_RESET request")};
    }

    auto control_response_res = m_connection->SendRequest(control_req_result.value());

    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation({actors::OP_ACTOR_MAC_HANDLER, mac_ops::MAC_RESET}).expectSuccess();

    if (!validator.isValid())
    {
        score::mw::log::LogError() << "[API][MacContextImpl] ERROR:" << validator.getError();
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "MAC_RESET daemon response invalid")};
    }

    return std::monostate{};
}

std::size_t MacContextImpl::GetMacSize() const noexcept
{
    return GetOutputSize();
}

std::size_t MacContextImpl::GetOutputSize() const noexcept
{
    auto control_req_result = proto::ControlRequestBuilder()
                                  .forDataNodeId(m_context_id)
                                  .operation({actors::OP_ACTOR_MAC_HANDLER, mac_ops::MAC_GET_SIZE})
                                  .build();
    if (!control_req_result.has_value())
    {
        score::mw::log::LogError() << "[API][MacContextImpl] ERROR: Failed to build MAC_GET_SIZE request";
        return 0;
    }

    auto control_response_res = m_connection->SendRequest(control_req_result.value());

    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation({actors::OP_ACTOR_MAC_HANDLER, mac_ops::MAC_GET_SIZE}).expectSuccess();

    if (!validator.isValid())
    {
        score::mw::log::LogError() << "[API][MacContextImpl] ERROR:" << validator.getError();
        return 0;
    }

    auto size_result = validator.getParameterAt<std::uint64_t>(0, 0);
    if (!size_result.has_value())
    {
        score::mw::log::LogError() << "[API][MacContextImpl] ERROR: MAC_GET_SIZE response has invalid parameter type";
        return 0;
    }

    return static_cast<std::size_t>(size_result.value());
}

score::Result<std::monostate> MacContextImpl::Init(std::optional<score::cpp::span<const uint8_t>> iv)
{
    if (iv.has_value())
    {
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kUnsupportedOperation, "Init with IV not yet supported")};
    }

    auto control_req_result = proto::ControlRequestBuilder()
                                  .forDataNodeId(m_context_id)
                                  .operation({actors::OP_ACTOR_MAC_HANDLER, mac_ops::MAC_INIT})
                                  .build();
    if (!control_req_result.has_value())
    {
        score::mw::log::LogError() << "[API][MacContextImpl] ERROR: Failed to build MAC_INIT request";
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build MAC_INIT request")};
    }

    auto control_response_res = m_connection->SendRequest(control_req_result.value());

    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation({actors::OP_ACTOR_MAC_HANDLER, mac_ops::MAC_INIT}).expectSuccess();

    if (!validator.isValid())
    {
        score::mw::log::LogError() << "[API][MacContextImpl] ERROR:" << validator.getError();
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "MAC_INIT daemon response invalid")};
    }

    return std::monostate{};
}

}  // namespace crypto

}  // namespace score

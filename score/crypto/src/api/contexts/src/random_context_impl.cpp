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

#include "score/crypto/src/api/contexts/src/random_context_impl.hpp"

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/common/types.hpp"

#include "score/crypto/src/api/control_plane/i_connection.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/random_handler_operations.hpp"

#include "score/result/result.h"
#include "score/span.hpp"

#include "score/mw/log/logging.h"
#include <cstdint>
#include <string_view>

#include <memory>
#include <utility>
#include <variant>

namespace score
{

namespace crypto
{

namespace
{
namespace proto = ::score::crypto::daemon::control_plane::protocol;
namespace actors = ::score::crypto::daemon::common::actors;
namespace random_ops = ::score::crypto::daemon::provider::handler::random_handler_operations;

constexpr std::string_view kLogPrefix = "[API][RandomContextImpl] ERROR: ";
}  // namespace

RandomContextImpl::RandomContextImpl(std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
                                     uint64_t context_id,
                                     AlgorithmId algorithm,
                                     std::shared_ptr<IBufferTranscoder> transcoder)
    : m_connection(std::move(connection)),
      m_context_id(context_id),
      m_algorithm(std::move(algorithm)),
      m_transcoder(std::move(transcoder))
{
}

RandomContextImpl::RandomContextImpl(RandomContextImpl&& other) noexcept
    : m_connection(std::move(other.m_connection)),
      m_context_id(std::exchange(other.m_context_id, 0)),
      m_algorithm(std::move(other.m_algorithm)),
      m_transcoder(std::move(other.m_transcoder))
{
}

RandomContextImpl& RandomContextImpl::operator=(RandomContextImpl&& other) noexcept
{
    if (this != &other)
    {
        CloseContext();
        m_connection = std::move(other.m_connection);
        m_context_id = std::exchange(other.m_context_id, 0);
        m_algorithm = std::move(other.m_algorithm);
        m_transcoder = std::move(other.m_transcoder);
    }
    return *this;
}

RandomContextImpl::~RandomContextImpl()
{
    CloseContext();
}

void RandomContextImpl::CloseContext() noexcept
{
    if (m_context_id == 0)
    {
        return;  // moved-from instance — nothing to close
    }

    if (!m_connection)
    {
        score::mw::log::LogError() << kLogPrefix << "Connection is not initialized during destruction";
        return;
    }

    auto context_close_res = proto::ControlRequestBuilder()
                                 .forDataNodeId(m_context_id)
                                 .operation(score::crypto::daemon::mediator::operations::CloseContext())
                                 .build();

    if (!context_close_res.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "Failed to build CTX_CLOSE request during destruction";
        return;
    }

    auto response_res = m_connection->SendRequest(context_close_res.value());

    auto validator = proto::ControlResponseValidator::FromResult(response_res);
    validator.expectOperation(score::crypto::daemon::mediator::operations::CloseContext()).expectSuccess();

    if (!validator.isValid())
    {
        score::mw::log::LogError() << kLogPrefix << "CTX_CLOSE response validation failed: " << validator.getError();
    }
}

score::Result<std::size_t> RandomContextImpl::Generate(score::cpp::span<uint8_t> output)
{
    if (output.empty())
    {
        return std::size_t{0U};
    }

    proto::OperationRequestBuilder builder;
    builder.operation({actors::OP_ACTOR_RANDOM_HANDLER, random_ops::RANDOM_GENERATE});

    auto tspan_result = m_transcoder->Acquire(output, /*is_output=*/true);
    if (!tspan_result.has_value())
    {
        return score::Result<std::size_t>{score::unexpect, tspan_result.error()};
    }
    TranscoderSpan tspan = std::move(tspan_result.value());
    m_transcoder->AppendOutputBuffer(builder, tspan);

    auto control_request_result = builder.build();
    if (!control_request_result.has_value())
    {
        return score::Result<std::size_t>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build RANDOM_GENERATE request")};
    }

    proto::ControlRequest control_req{};
    control_req.operation = control_request_result.value();
    control_req.data_node_id = m_context_id;
    auto control_response_res = m_connection->SendRequest(control_req);

    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation({actors::OP_ACTOR_RANDOM_HANDLER, random_ops::RANDOM_GENERATE}).expectSuccess();

    if (!validator.isValid())
    {
        return score::Result<std::size_t>{score::unexpect,
                                          MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    }

    auto written = m_transcoder->ExtractOutputBuffer(tspan, validator);
    if (!written.has_value())
    {
        return written;
    }

    // The daemon must fill the whole buffer. A short write would silently leave
    // part of it unrandomised, so it is reported as an error rather than a
    // partial result the caller might use as key or IV material.
    if (written.value() != output.size())
    {
        score::mw::log::LogError() << kLogPrefix << "RANDOM_GENERATE produced" << written.value() << "bytes, expected"
                                   << output.size();
        return score::Result<std::size_t>{
            score::unexpect,
            MakeError(CryptoErrorCode::kOperationFailed, "RANDOM_GENERATE returned an unexpected byte count")};
    }

    return written;
}

score::Result<std::monostate> RandomContextImpl::Seed(score::cpp::span<const uint8_t> seed)
{
    proto::OperationRequestBuilder builder;
    builder.operation({actors::OP_ACTOR_RANDOM_HANDLER, random_ops::RANDOM_SEED});

    auto tspan_result = m_transcoder->Acquire(seed);
    if (!tspan_result.has_value())
    {
        return score::Result<std::monostate>{score::unexpect, tspan_result.error()};
    }
    TranscoderSpan tspan = std::move(tspan_result.value());
    m_transcoder->AppendInputBuffer(builder, tspan);

    auto control_request_result = builder.build();
    if (!control_request_result.has_value())
    {
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build RANDOM_SEED request")};
    }

    proto::ControlRequest control_req{};
    control_req.operation = control_request_result.value();
    control_req.data_node_id = m_context_id;
    auto control_response_res = m_connection->SendRequest(control_req);

    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation({actors::OP_ACTOR_RANDOM_HANDLER, random_ops::RANDOM_SEED}).expectSuccess();

    if (!validator.isValid())
    {
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    }

    return std::monostate{};
}

}  // namespace crypto

}  // namespace score

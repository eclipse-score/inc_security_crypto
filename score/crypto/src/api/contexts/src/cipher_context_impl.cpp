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

#include "score/crypto/src/api/contexts/src/cipher_context_impl.hpp"

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/common/types.hpp"

#include "score/crypto/src/api/control_plane/i_connection.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/cipher_handler_operations.hpp"

#include "score/result/result.h"
#include "score/span.hpp"

#include "score/mw/log/logging.h"
#include <cstdint>
#include <string_view>

#include <memory>
#include <optional>
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
namespace cipher_ops = ::score::crypto::daemon::provider::handler::cipher_handler_operations;

constexpr std::string_view kLogPrefix = "[API][CipherContextImpl] ERROR: ";
}  // namespace

CipherContextImpl::CipherContextImpl(std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
                                     uint64_t context_id,
                                     AlgorithmId algorithm,
                                     std::shared_ptr<IBufferTranscoder> transcoder)
    : m_connection(std::move(connection)),
      m_context_id(context_id),
      m_algorithm(std::move(algorithm)),
      m_transcoder(std::move(transcoder))
{
}

CipherContextImpl::CipherContextImpl(CipherContextImpl&& other) noexcept
    : m_connection(std::move(other.m_connection)),
      m_context_id(std::exchange(other.m_context_id, 0)),
      m_algorithm(std::move(other.m_algorithm)),
      m_transcoder(std::move(other.m_transcoder))
{
}

CipherContextImpl& CipherContextImpl::operator=(CipherContextImpl&& other) noexcept
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

CipherContextImpl::~CipherContextImpl()
{
    CloseContext();
}

void CipherContextImpl::CloseContext() noexcept
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

score::Result<std::monostate> CipherContextImpl::Init(std::optional<score::cpp::span<const uint8_t>> iv)
{
    proto::OperationRequestBuilder builder;
    builder.operation({actors::OP_ACTOR_CIPHER_HANDLER, cipher_ops::CIPHER_INIT});

    // IV-less modes (ECB) pass std::nullopt; the daemon rejects a missing IV for
    // modes that require one, so no client-side algorithm table is needed here.
    // The token has to outlive build() and SendRequest(): a pool slot is released
    // by ~TranscoderSpan, and the daemon reads the slot while the call is in flight.
    TranscoderSpan iv_tspan;
    if (iv.has_value())
    {
        auto iv_tspan_result = m_transcoder->Acquire(iv.value());
        if (!iv_tspan_result.has_value())
        {
            return score::Result<std::monostate>{score::unexpect, iv_tspan_result.error()};
        }
        iv_tspan = std::move(iv_tspan_result.value());
        m_transcoder->AppendInputBuffer(builder, iv_tspan);
    }

    auto control_request_result = builder.build();
    if (!control_request_result.has_value())
    {
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build CIPHER_INIT request")};
    }

    proto::ControlRequest control_req{};
    control_req.operation = control_request_result.value();
    control_req.data_node_id = m_context_id;
    auto control_response_res = m_connection->SendRequest(control_req);

    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation({actors::OP_ACTOR_CIPHER_HANDLER, cipher_ops::CIPHER_INIT}).expectSuccess();

    if (!validator.isValid())
    {
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    }

    return std::monostate{};
}

score::Result<std::monostate> CipherContextImpl::Update(score::cpp::span<const uint8_t> /*data*/)
{
    // A cipher Update always produces output, so the output-less streaming
    // signature inherited from IStreamingContext cannot be honoured. Callers
    // use the ICipherContext::Update(input, output) overload instead.
    return score::Result<std::monostate>{
        score::unexpect, MakeError(CryptoErrorCode::kUnsupportedOperation, "Cipher Update requires an output buffer")};
}

score::Result<std::size_t> CipherContextImpl::Update(score::cpp::span<const uint8_t> input,
                                                     score::cpp::span<uint8_t> output)
{
    proto::OperationRequestBuilder builder;
    builder.operation({actors::OP_ACTOR_CIPHER_HANDLER, cipher_ops::CIPHER_UPDATE});

    auto input_tspan_result = m_transcoder->Acquire(input);
    if (!input_tspan_result.has_value())
    {
        return score::Result<std::size_t>{score::unexpect, input_tspan_result.error()};
    }
    TranscoderSpan input_tspan = std::move(input_tspan_result.value());
    m_transcoder->AppendInputBuffer(builder, input_tspan);

    auto output_tspan_result = m_transcoder->Acquire(output, /*is_output=*/true);
    if (!output_tspan_result.has_value())
    {
        return score::Result<std::size_t>{score::unexpect, output_tspan_result.error()};
    }
    TranscoderSpan output_tspan = std::move(output_tspan_result.value());
    m_transcoder->AppendOutputBuffer(builder, output_tspan);

    auto control_request_result = builder.build();
    if (!control_request_result.has_value())
    {
        return score::Result<std::size_t>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build CIPHER_UPDATE request")};
    }

    proto::ControlRequest control_req{};
    control_req.operation = control_request_result.value();
    control_req.data_node_id = m_context_id;
    auto control_response_res = m_connection->SendRequest(control_req);

    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation({actors::OP_ACTOR_CIPHER_HANDLER, cipher_ops::CIPHER_UPDATE}).expectSuccess();

    if (!validator.isValid())
    {
        return score::Result<std::size_t>{score::unexpect,
                                          MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    }

    return m_transcoder->ExtractOutputBuffer(output_tspan, validator);
}

score::Result<std::size_t> CipherContextImpl::Finalize(score::cpp::span<uint8_t> output)
{
    proto::OperationRequestBuilder builder;
    builder.operation({actors::OP_ACTOR_CIPHER_HANDLER, cipher_ops::CIPHER_FINALIZE});

    auto output_tspan_result = m_transcoder->Acquire(output, /*is_output=*/true);
    if (!output_tspan_result.has_value())
    {
        return score::Result<std::size_t>{score::unexpect, output_tspan_result.error()};
    }
    TranscoderSpan output_tspan = std::move(output_tspan_result.value());
    m_transcoder->AppendOutputBuffer(builder, output_tspan);

    auto control_request_result = builder.build();
    if (!control_request_result.has_value())
    {
        return score::Result<std::size_t>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build CIPHER_FINALIZE request")};
    }

    proto::ControlRequest control_req{};
    control_req.operation = control_request_result.value();
    control_req.data_node_id = m_context_id;
    auto control_response_res = m_connection->SendRequest(control_req);

    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation({actors::OP_ACTOR_CIPHER_HANDLER, cipher_ops::CIPHER_FINALIZE}).expectSuccess();

    if (!validator.isValid())
    {
        return score::Result<std::size_t>{score::unexpect,
                                          MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    }

    return m_transcoder->ExtractOutputBuffer(output_tspan, validator);
}

score::Result<std::size_t> CipherContextImpl::SingleShot(score::cpp::span<const uint8_t> iv,
                                                         score::cpp::span<const uint8_t> input,
                                                         score::cpp::span<uint8_t> output)
{
    proto::OperationRequestBuilder builder;
    builder.operation({actors::OP_ACTOR_CIPHER_HANDLER, cipher_ops::CIPHER_SS});

    // The IV slot is always sent, empty for ECB, so that the input and output
    // buffers keep fixed positions on the wire.
    auto iv_tspan_result = m_transcoder->Acquire(iv);
    if (!iv_tspan_result.has_value())
    {
        return score::Result<std::size_t>{score::unexpect, iv_tspan_result.error()};
    }
    TranscoderSpan iv_tspan = std::move(iv_tspan_result.value());
    m_transcoder->AppendInputBuffer(builder, iv_tspan);

    auto input_tspan_result = m_transcoder->Acquire(input);
    if (!input_tspan_result.has_value())
    {
        return score::Result<std::size_t>{score::unexpect, input_tspan_result.error()};
    }
    TranscoderSpan input_tspan = std::move(input_tspan_result.value());
    m_transcoder->AppendInputBuffer(builder, input_tspan);

    auto output_tspan_result = m_transcoder->Acquire(output, /*is_output=*/true);
    if (!output_tspan_result.has_value())
    {
        return score::Result<std::size_t>{score::unexpect, output_tspan_result.error()};
    }
    TranscoderSpan output_tspan = std::move(output_tspan_result.value());
    m_transcoder->AppendOutputBuffer(builder, output_tspan);

    auto control_request_result = builder.build();
    if (!control_request_result.has_value())
    {
        return score::Result<std::size_t>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build CIPHER_SS request")};
    }

    proto::ControlRequest control_req{};
    control_req.operation = control_request_result.value();
    control_req.data_node_id = m_context_id;
    auto control_response_res = m_connection->SendRequest(control_req);

    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation({actors::OP_ACTOR_CIPHER_HANDLER, cipher_ops::CIPHER_SS}).expectSuccess();

    if (!validator.isValid())
    {
        return score::Result<std::size_t>{score::unexpect,
                                          MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    }

    return m_transcoder->ExtractOutputBuffer(output_tspan, validator);
}

score::Result<std::monostate> CipherContextImpl::Reset()
{
    auto control_req_result = proto::ControlRequestBuilder()
                                  .forDataNodeId(m_context_id)
                                  .operation({actors::OP_ACTOR_CIPHER_HANDLER, cipher_ops::CIPHER_RESET})
                                  .build();
    if (!control_req_result.has_value())
    {
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build CIPHER_RESET request")};
    }

    auto control_response_res = m_connection->SendRequest(control_req_result.value());

    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation({actors::OP_ACTOR_CIPHER_HANDLER, cipher_ops::CIPHER_RESET}).expectSuccess();

    if (!validator.isValid())
    {
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    }

    return std::monostate{};
}

std::size_t CipherContextImpl::GetOutputSize() const noexcept
{
    auto control_req_result = proto::ControlRequestBuilder()
                                  .forDataNodeId(m_context_id)
                                  .operation({actors::OP_ACTOR_CIPHER_HANDLER, cipher_ops::CIPHER_GET_OUTPUT_SIZE})
                                  .build();
    if (!control_req_result.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "Failed to build CIPHER_GET_OUTPUT_SIZE request";
        return 0U;
    }

    auto control_response_res = m_connection->SendRequest(control_req_result.value());

    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation({actors::OP_ACTOR_CIPHER_HANDLER, cipher_ops::CIPHER_GET_OUTPUT_SIZE}).expectSuccess();

    if (!validator.isValid())
    {
        score::mw::log::LogError() << kLogPrefix << validator.getError();
        return 0U;
    }

    auto size_result = validator.getParameterAt<std::uint64_t>(0, 0);
    if (!size_result.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "CIPHER_GET_OUTPUT_SIZE response has invalid parameter type";
        return 0U;
    }

    return static_cast<std::size_t>(size_result.value());
}

}  // namespace crypto

}  // namespace score

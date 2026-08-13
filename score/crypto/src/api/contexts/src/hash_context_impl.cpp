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

#include "score/crypto/src/api/contexts/src/hash_context_impl.hpp"

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/common/types.hpp"

#include "score/crypto/src/api/control_plane/i_connection.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/hash_handler_operations.hpp"

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
namespace hash_ops = ::score::crypto::daemon::provider::handler::hash_handler_operations;

HashContextImpl::HashContextImpl(std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
                                 uint64_t context_id,
                                 AlgorithmId algorithm,
                                 std::shared_ptr<IBufferTranscoder> transcoder)
    : m_connection(std::move(connection)),
      m_context_id(context_id),
      m_algorithm(algorithm),
      m_transcoder(std::move(transcoder))
{
}

HashContextImpl::HashContextImpl(HashContextImpl&& other) noexcept
    : m_connection(std::move(other.m_connection)),
      m_context_id(std::exchange(other.m_context_id, 0)),
      m_algorithm(other.m_algorithm),
      m_transcoder(std::move(other.m_transcoder))
{
}

HashContextImpl& HashContextImpl::operator=(HashContextImpl&& other) noexcept
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

HashContextImpl::~HashContextImpl()
{
    CloseContext();
}

void HashContextImpl::CloseContext() noexcept
{
    if (m_context_id == 0)
    {
        return;  // moved-from instance — nothing to close
    }

    if (!m_connection)
    {
        score::mw::log::LogError() << "[API][HashContextImpl] ERROR: Connection is not initialized during destruction";
        return;
    }

    // Build CONTEXT_CLOSE request
    auto context_close_res = proto::ControlRequestBuilder()
                                 .forDataNodeId(m_context_id)
                                 .operation(score::crypto::daemon::mediator::operations::CloseContext())
                                 .build();

    if (!context_close_res.has_value())
    {
        score::mw::log::LogError()
            << "[API][HashContextImpl] ERROR: Failed to build CTX_CLOSE request during destruction";
        return;
    }

    // Send CTX_CLOSE request to daemon
    auto response_res = m_connection->SendRequest(context_close_res.value());

    // Validate response using ControlResponseValidator
    auto validator = proto::ControlResponseValidator::FromResult(response_res);
    validator.expectOperation(score::crypto::daemon::mediator::operations::CloseContext()).expectSuccess();

    if (!validator.isValid())
    {
        score::mw::log::LogError() << "[API][HashContextImpl] ERROR: CTX_CLOSE response validation failed: "
                                   << validator.getError();
        return;
    }
}

score::Result<std::monostate> HashContextImpl::Init(std::optional<score::cpp::span<const uint8_t>> iv)
{
    if (iv.has_value())
    {
        return score::Result<std::monostate>{
            score::unexpect,
            MakeError(CryptoErrorCode::kUnsupportedOperation, "Init with IV not supported for hash contexts")};
    }

    auto control_req_result = proto::ControlRequestBuilder()
                                  .forDataNodeId(m_context_id)
                                  .operation({actors::OP_ACTOR_HASH_HANDLER, hash_ops::HASH_INIT})
                                  .build();
    if (!control_req_result.has_value())
    {
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build HASH_INIT request")};
    }

    // Send HASH_INIT request to daemon
    auto control_response_res = m_connection->SendRequest(control_req_result.value());

    // Validate HASH_INIT response
    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation({actors::OP_ACTOR_HASH_HANDLER, hash_ops::HASH_INIT}).expectSuccess();

    if (!validator.isValid())
    {
        // TODO(error-unification phase-4): Extract the specific CryptoErrorCode from the daemon
        // response (via validator.getErrorCode() or ControlResponseValidator extension) and
        // return it directly instead of the generic kOperationFailed. This gives callers
        // actionable error information (e.g. kStreamNotInitialized vs kAlgorithmExecutionFailed)
        // rather than a single catch-all code. Applies to all Init/Update/Finalize/SingleShot
        // operations in every context impl (hash, mac, cipher, key_mgmt).
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    }

    return std::monostate{};
}

score::Result<std::monostate> HashContextImpl::Update(score::cpp::span<const uint8_t> data)
{
    proto::OperationRequestBuilder builder;
    builder.operation({actors::OP_ACTOR_HASH_HANDLER, hash_ops::HASH_UPDATE});

    auto tspan_result = m_transcoder->Acquire(data);
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
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build HASH_UPDATE request")};
    }

    proto::ControlRequest control_req{};
    control_req.operation = control_request_result.value();
    control_req.data_node_id = m_context_id;
    auto control_response_res = m_connection->SendRequest(control_req);

    // Validate HASH_UPDATE response
    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation({actors::OP_ACTOR_HASH_HANDLER, hash_ops::HASH_UPDATE}).expectSuccess();

    if (!validator.isValid())
    {
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    }

    return std::monostate{};
}

score::Result<std::size_t> HashContextImpl::Finalize(score::cpp::span<uint8_t> output)
{
    proto::OperationRequestBuilder builder;
    builder.operation({actors::OP_ACTOR_HASH_HANDLER, hash_ops::HASH_FINALIZE});

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
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build HASH_FINALIZE request")};
    }

    proto::ControlRequest control_req{};
    control_req.operation = control_request_result.value();
    control_req.data_node_id = m_context_id;
    auto control_response_res = m_connection->SendRequest(control_req);

    // Validate HASH_FINALIZE response
    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation({actors::OP_ACTOR_HASH_HANDLER, hash_ops::HASH_FINALIZE}).expectSuccess();

    if (!validator.isValid())
    {
        return score::Result<std::size_t>{score::unexpect,
                                          MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    }

    return m_transcoder->ExtractOutputBuffer(tspan, validator);
}

score::Result<std::size_t> HashContextImpl::SingleShot(score::cpp::span<const uint8_t> input,
                                                       score::cpp::span<uint8_t> output)
{
    proto::OperationRequestBuilder builder;
    builder.operation({actors::OP_ACTOR_HASH_HANDLER, hash_ops::HASH_SS});

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
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build HASH_SS request")};
    }

    proto::ControlRequest control_req{};
    control_req.operation = control_request_result.value();
    control_req.data_node_id = m_context_id;
    auto control_response_res = m_connection->SendRequest(control_req);

    // Validate HASH_SS response
    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation({actors::OP_ACTOR_HASH_HANDLER, hash_ops::HASH_SS}).expectSuccess();

    if (!validator.isValid())
    {
        return score::Result<std::size_t>{score::unexpect,
                                          MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    }

    return m_transcoder->ExtractOutputBuffer(output_tspan, validator);
}

score::Result<std::monostate> HashContextImpl::Reset()
{
    auto control_req_result = proto::ControlRequestBuilder()
                                  .forDataNodeId(m_context_id)
                                  .operation({actors::OP_ACTOR_HASH_HANDLER, hash_ops::HASH_RESET})
                                  .build();
    if (!control_req_result.has_value())
    {
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build HASH_RESET request")};
    }

    // Send HASH_RESET request to daemon
    auto control_response_res = m_connection->SendRequest(control_req_result.value());

    // Validate HASH_RESET response
    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation({actors::OP_ACTOR_HASH_HANDLER, hash_ops::HASH_RESET}).expectSuccess();

    if (!validator.isValid())
    {
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    }

    return std::monostate{};
}

std::size_t HashContextImpl::GetDigestSize() const noexcept
{
    // For hash contexts, digest size and output size are the same.
    return GetOutputSize();
}

std::size_t HashContextImpl::GetOutputSize() const noexcept
{
    auto control_req_result = proto::ControlRequestBuilder()
                                  .forDataNodeId(m_context_id)
                                  .operation({actors::OP_ACTOR_HASH_HANDLER, hash_ops::HASH_GET_DIGEST_SIZE})
                                  .build();
    if (!control_req_result.has_value())
    {
        score::mw::log::LogError() << "[API][HashContextImpl] ERROR: Failed to build HASH_GET_DIGEST_SIZE request";
        return 0;
    }

    // Send HASH_GET_DIGEST_SIZE request to daemon
    auto control_response_res = m_connection->SendRequest(control_req_result.value());

    // Validate HASH_GET_DIGEST_SIZE response
    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation({actors::OP_ACTOR_HASH_HANDLER, hash_ops::HASH_GET_DIGEST_SIZE}).expectSuccess();

    if (!validator.isValid())
    {
        score::mw::log::LogError() << "[API][HashContextImpl] ERROR:" << validator.getError();
        return 0;
    }

    auto size_result = validator.getParameterAt<std::uint64_t>(0, 0);
    if (!size_result.has_value())
    {
        score::mw::log::LogError()
            << "[API][HashContextImpl] ERROR: HASH_GET_DIGEST_SIZE response has invalid parameter type";
        return 0;
    }

    return static_cast<std::size_t>(size_result.value());
}

}  // namespace crypto

}  // namespace score

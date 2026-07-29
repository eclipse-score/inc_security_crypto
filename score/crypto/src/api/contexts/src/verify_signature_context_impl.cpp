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

#include "score/crypto/src/api/contexts/src/verify_signature_context_impl.hpp"

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/common/types.hpp"

#include "score/crypto/src/api/control_plane/i_connection.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/signature_handler_operations.hpp"

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
namespace verify_ops = ::score::crypto::daemon::provider::handler::verify_handler_operations;

constexpr std::string_view kLogPrefix = "[API][VerifySignatureContextImpl] ERROR: ";
}  // namespace

VerifySignatureContextImpl::VerifySignatureContextImpl(
    std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
    uint64_t context_id,
    AlgorithmId algorithm,
    std::shared_ptr<IBufferTranscoder> transcoder)
    : m_connection(std::move(connection)),
      m_context_id(context_id),
      m_algorithm(std::move(algorithm)),
      m_transcoder(std::move(transcoder))
{
}

VerifySignatureContextImpl::VerifySignatureContextImpl(VerifySignatureContextImpl&& other) noexcept
    : m_connection(std::move(other.m_connection)),
      m_context_id(std::exchange(other.m_context_id, 0)),
      m_algorithm(std::move(other.m_algorithm)),
      m_transcoder(std::move(other.m_transcoder))
{
}

VerifySignatureContextImpl& VerifySignatureContextImpl::operator=(VerifySignatureContextImpl&& other) noexcept
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

VerifySignatureContextImpl::~VerifySignatureContextImpl()
{
    CloseContext();
}

void VerifySignatureContextImpl::CloseContext() noexcept
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

score::Result<std::monostate> VerifySignatureContextImpl::Init(std::optional<score::cpp::span<const uint8_t>> iv)
{
    if (iv.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "Init with an IV is not applicable to a verification context";
        return score::Result<std::monostate>{
            score::unexpect,
            MakeError(CryptoErrorCode::kUnsupportedOperation, "Verification contexts do not take an IV")};
    }

    auto control_req_result = proto::ControlRequestBuilder()
                                  .forDataNodeId(m_context_id)
                                  .operation({actors::OP_ACTOR_VERIFY_HANDLER, verify_ops::VERIFY_INIT})
                                  .build();
    if (!control_req_result.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "Failed to build VERIFY_INIT request";
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build VERIFY_INIT request")};
    }

    auto control_response_res = m_connection->SendRequest(control_req_result.value());

    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation({actors::OP_ACTOR_VERIFY_HANDLER, verify_ops::VERIFY_INIT}).expectSuccess();

    if (!validator.isValid())
    {
        score::mw::log::LogError() << kLogPrefix << validator.getError();
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "VERIFY_INIT daemon response invalid")};
    }

    return std::monostate{};
}

score::Result<std::monostate> VerifySignatureContextImpl::Update(score::cpp::span<const uint8_t> data)
{
    proto::OperationRequestBuilder builder;
    builder.operation({actors::OP_ACTOR_VERIFY_HANDLER, verify_ops::VERIFY_UPDATE});

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
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build VERIFY_UPDATE request")};
    }

    proto::ControlRequest control_req{};
    control_req.operation = control_request_result.value();
    control_req.data_node_id = m_context_id;
    auto control_response_res = m_connection->SendRequest(control_req);

    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation({actors::OP_ACTOR_VERIFY_HANDLER, verify_ops::VERIFY_UPDATE}).expectSuccess();

    if (!validator.isValid())
    {
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    }

    return std::monostate{};
}

score::Result<bool> VerifySignatureContextImpl::VerifyFinalize(score::cpp::span<const uint8_t> signature)
{
    proto::OperationRequestBuilder builder;
    builder.operation({actors::OP_ACTOR_VERIFY_HANDLER, verify_ops::VERIFY_FINALIZE});

    auto tspan_result = m_transcoder->Acquire(signature);
    if (!tspan_result.has_value())
    {
        return score::Result<bool>{score::unexpect, tspan_result.error()};
    }
    TranscoderSpan tspan = std::move(tspan_result.value());
    m_transcoder->AppendInputBuffer(builder, tspan);

    auto control_request_result = builder.build();
    if (!control_request_result.has_value())
    {
        return score::Result<bool>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build VERIFY_FINALIZE request")};
    }

    proto::ControlRequest control_req{};
    control_req.operation = control_request_result.value();
    control_req.data_node_id = m_context_id;
    auto control_response_res = m_connection->SendRequest(control_req);

    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation({actors::OP_ACTOR_VERIFY_HANDLER, verify_ops::VERIFY_FINALIZE}).expectSuccess();

    if (!validator.isValid())
    {
        return score::Result<bool>{score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    }

    auto verify_result = validator.getParameterAt<bool>(0, 0);
    if (!verify_result.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "VERIFY_FINALIZE response has invalid parameter type";
        return score::Result<bool>{
            score::unexpect,
            MakeError(CryptoErrorCode::kOperationFailed, "VERIFY_FINALIZE response has invalid parameter type")};
    }

    return verify_result.value();
}

score::Result<bool> VerifySignatureContextImpl::SingleShot(score::cpp::span<const uint8_t> data,
                                                           score::cpp::span<const uint8_t> signature)
{
    proto::OperationRequestBuilder builder;
    builder.operation({actors::OP_ACTOR_VERIFY_HANDLER, verify_ops::VERIFY_SS});

    auto data_tspan_result = m_transcoder->Acquire(data);
    if (!data_tspan_result.has_value())
    {
        return score::Result<bool>{score::unexpect, data_tspan_result.error()};
    }
    TranscoderSpan data_tspan = std::move(data_tspan_result.value());
    m_transcoder->AppendInputBuffer(builder, data_tspan);

    auto sig_tspan_result = m_transcoder->Acquire(signature);
    if (!sig_tspan_result.has_value())
    {
        return score::Result<bool>{score::unexpect, sig_tspan_result.error()};
    }
    TranscoderSpan sig_tspan = std::move(sig_tspan_result.value());
    m_transcoder->AppendInputBuffer(builder, sig_tspan);

    auto control_request_result = builder.build();
    if (!control_request_result.has_value())
    {
        return score::Result<bool>{score::unexpect,
                                   MakeError(CryptoErrorCode::kOperationFailed, "Failed to build VERIFY_SS request")};
    }

    proto::ControlRequest control_req{};
    control_req.operation = control_request_result.value();
    control_req.data_node_id = m_context_id;
    auto control_response_res = m_connection->SendRequest(control_req);

    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation({actors::OP_ACTOR_VERIFY_HANDLER, verify_ops::VERIFY_SS}).expectSuccess();

    if (!validator.isValid())
    {
        return score::Result<bool>{score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    }

    auto verify_result = validator.getParameterAt<bool>(0, 0);
    if (!verify_result.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "VERIFY_SS response has invalid parameter type";
        return score::Result<bool>{
            score::unexpect,
            MakeError(CryptoErrorCode::kOperationFailed, "VERIFY_SS response has invalid parameter type")};
    }

    return verify_result.value();
}

score::Result<std::monostate> VerifySignatureContextImpl::Reset()
{
    auto control_req_result = proto::ControlRequestBuilder()
                                  .forDataNodeId(m_context_id)
                                  .operation({actors::OP_ACTOR_VERIFY_HANDLER, verify_ops::VERIFY_RESET})
                                  .build();
    if (!control_req_result.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "Failed to build VERIFY_RESET request";
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build VERIFY_RESET request")};
    }

    auto control_response_res = m_connection->SendRequest(control_req_result.value());

    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation({actors::OP_ACTOR_VERIFY_HANDLER, verify_ops::VERIFY_RESET}).expectSuccess();

    if (!validator.isValid())
    {
        score::mw::log::LogError() << kLogPrefix << validator.getError();
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "VERIFY_RESET daemon response invalid")};
    }

    return std::monostate{};
}

}  // namespace crypto

}  // namespace score

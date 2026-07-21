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

#include "score/mw/crypto/api/contexts/src/mac_context_impl.hpp"

#include "score/mw/crypto/api/common/error_domain.hpp"
#include "score/mw/crypto/api/common/types.hpp"

#include "score/crypto/api/control_plane/i_connection.hpp"
#include "score/crypto/daemon/common/actors.hpp"
#include "score/crypto/daemon/control_plane/control_protocol.h"
#include "score/crypto/daemon/mediator/mediator_operations.hpp"
#include "score/crypto/daemon/provider/handler/operations/mac_handler_operations.hpp"

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
namespace mw
{
namespace crypto
{

namespace proto = ::score::crypto::daemon::control_plane::protocol;
namespace actors = ::score::crypto::daemon::common::actors;
namespace mac_ops = ::score::crypto::daemon::provider::handler::mac_handler_operations;

MacContextImpl::MacContextImpl(std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
                               uint64_t context_id,
                               AlgorithmId algorithm)
    : m_connection(std::move(connection)), m_context_id(context_id), m_algorithm(algorithm)
{
}

MacContextImpl::~MacContextImpl()
{
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
    auto control_req_result = proto::ControlRequestBuilder()
                                  .forDataNodeId(m_context_id)
                                  .operation({actors::OP_ACTOR_MAC_HANDLER, mac_ops::MAC_UPDATE})
                                  .with_in_data_buffer(data)
                                  .build();
    if (!control_req_result.has_value())
    {
        score::mw::log::LogError() << "[API][MacContextImpl] ERROR: Failed to build MAC_UPDATE request";
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build MAC_UPDATE request")};
    }

    auto control_response_res = m_connection->SendRequest(control_req_result.value());

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
    auto control_req_result = proto::ControlRequestBuilder()
                                  .forDataNodeId(m_context_id)
                                  .operation({actors::OP_ACTOR_MAC_HANDLER, mac_ops::MAC_FINALIZE})
                                  .build();
    if (!control_req_result.has_value())
    {
        score::mw::log::LogError() << "[API][MacContextImpl] ERROR: Failed to build MAC_FINALIZE request";
        return score::Result<std::size_t>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build MAC_FINALIZE request")};
    }

    auto control_response_res = m_connection->SendRequest(control_req_result.value());

    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation({actors::OP_ACTOR_MAC_HANDLER, mac_ops::MAC_FINALIZE}).expectSuccess();

    if (!validator.isValid())
    {
        score::mw::log::LogError() << "[API][MacContextImpl] ERROR:" << validator.getError();
        return score::Result<std::size_t>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "MAC_FINALIZE daemon response invalid")};
    }

    auto mac_result = validator.getParameterAt<proto::DataBufferReturn>(0, 0);
    if (!mac_result.has_value())
    {
        score::mw::log::LogError() << "[API][MacContextImpl] ERROR: MAC_FINALIZE response has invalid parameter type";
        return score::Result<std::size_t>{
            score::unexpect,
            MakeError(CryptoErrorCode::kOperationFailed, "MAC_FINALIZE response has invalid parameter type")};
    }

    const auto& mac_data = mac_result.value();
    auto bytes_to_copy = std::min(mac_data.size(), output.size());
    std::memcpy(output.data(), mac_data.data(), bytes_to_copy);

    // TODO: Consider if we should just abort here and not write anything to the output buffer
    // We may also be able to get the required out size as soon as we have created the ctx
    // at least a sub-set of operations / algorithms.
    if (bytes_to_copy < mac_data.size())
    {
        score::mw::log::LogError()
            << "[API][MacContextImpl] ERROR: Output buffer too small for full MAC tag, truncated copy performed";
        return score::Result<std::size_t>{
            score::unexpect,
            MakeError(CryptoErrorCode::kInsufficientBufferSize,
                      "ERROR: Output buffer too small for full MAC tag, truncated copy performed")};
    }

    return bytes_to_copy;
}

score::Result<bool> MacContextImpl::Verify(score::cpp::span<const uint8_t> mac)
{
    auto control_req_result = proto::ControlRequestBuilder()
                                  .forDataNodeId(m_context_id)
                                  .operation({actors::OP_ACTOR_MAC_HANDLER, mac_ops::MAC_VERIFY})
                                  .with_in_data_buffer(mac)
                                  .build();
    if (!control_req_result.has_value())
    {
        score::mw::log::LogError() << "[API][MacContextImpl] ERROR: Failed to build MAC_VERIFY request";
        return score::Result<bool>{score::unexpect,
                                   MakeError(CryptoErrorCode::kOperationFailed, "Failed to build MAC_VERIFY request")};
    }

    auto control_response_res = m_connection->SendRequest(control_req_result.value());

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
}  // namespace mw
}  // namespace score

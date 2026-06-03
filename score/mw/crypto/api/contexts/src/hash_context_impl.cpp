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

#include "score/mw/crypto/api/contexts/src/hash_context_impl.hpp"

#include "score/mw/crypto/api/common/error_domain.hpp"
#include "score/mw/crypto/api/common/types.hpp"

#include "score/crypto/api/control_plane/i_connection.hpp"
#include "score/crypto/daemon/common/actors.hpp"
#include "score/crypto/daemon/control_plane/control_protocol.h"
#include "score/crypto/daemon/mediator/mediator_operations.hpp"
#include "score/crypto/daemon/provider/handler/operations/hash_handler_operations.hpp"

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
namespace hash_ops = ::score::crypto::daemon::provider::handler::hash_handler_operations;

HashContextImpl::HashContextImpl(std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
                                 uint64_t context_id,
                                 AlgorithmId algorithm)
    : m_connection(std::move(connection)), m_context_id(context_id), m_algorithm(algorithm)
{
}

HashContextImpl::~HashContextImpl()
{
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
        score::mw::log::LogError() << "[API][HashContextImpl] ERROR: Failed to build HASH_INIT request";
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
        score::mw::log::LogError() << "[API][HashContextImpl] ERROR:" << validator.getError();
        // TODO(error-unification phase-4): Extract the specific CryptoErrorCode from the daemon
        // response (via validator.getErrorCode() or ControlResponseValidator extension) and
        // return it directly instead of the generic kOperationFailed. This gives callers
        // actionable error information (e.g. kStreamNotInitialized vs kAlgorithmExecutionFailed)
        // rather than a single catch-all code. Applies to all Init/Update/Finalize/SingleShot
        // operations in every context impl (hash, mac, cipher, key_mgmt).
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "HASH_INIT daemon response invalid")};
    }

    return std::monostate{};
}

score::Result<std::monostate> HashContextImpl::Update(score::cpp::span<const uint8_t> data)
{
    auto control_req_result = proto::ControlRequestBuilder()
                                  .forDataNodeId(m_context_id)
                                  .operation({actors::OP_ACTOR_HASH_HANDLER, hash_ops::HASH_UPDATE})
                                  .with_in_data_buffer(data)
                                  .build();
    if (!control_req_result.has_value())
    {
        score::mw::log::LogError() << "[API][HashContextImpl] ERROR: Failed to build HASH_UPDATE request";
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build HASH_UPDATE request")};
    }

    // Send HASH_UPDATE request to daemon
    auto control_response_res = m_connection->SendRequest(control_req_result.value());

    // Validate HASH_UPDATE response
    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation({actors::OP_ACTOR_HASH_HANDLER, hash_ops::HASH_UPDATE}).expectSuccess();

    if (!validator.isValid())
    {
        score::mw::log::LogError() << "[API][HashContextImpl] ERROR:" << validator.getError();
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "HASH_UPDATE daemon response invalid")};
    }

    return std::monostate{};
}

score::Result<std::size_t> HashContextImpl::Finalize(score::cpp::span<uint8_t> output)
{
    using proto::DataBufferReturn;

    auto control_req_result = proto::ControlRequestBuilder()
                                  .forDataNodeId(m_context_id)
                                  .operation({actors::OP_ACTOR_HASH_HANDLER, hash_ops::HASH_FINALIZE})
                                  .build();
    if (!control_req_result.has_value())
    {
        score::mw::log::LogError() << "[API][HashContextImpl] ERROR: Failed to build HASH_FINALIZE request";
        return score::Result<std::size_t>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build HASH_FINALIZE request")};
    }

    // Send HASH_FINALIZE request to daemon
    auto control_response_res = m_connection->SendRequest(control_req_result.value());

    // Validate HASH_FINALIZE response
    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation({actors::OP_ACTOR_HASH_HANDLER, hash_ops::HASH_FINALIZE}).expectSuccess();

    if (!validator.isValid())
    {
        score::mw::log::LogError() << "[API][HashContextImpl] ERROR:" << validator.getError();
        return score::Result<std::size_t>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "HASH_FINALIZE daemon response invalid")};
    }

    auto hash_result = validator.getParameterAt<proto::DataBufferReturn>(0, 0);
    if (!hash_result.has_value())
    {
        score::mw::log::LogError() << "[API][HashContextImpl] ERROR: HASH_FINALIZE response has invalid parameter type";
        return score::Result<std::size_t>{
            score::unexpect,
            MakeError(CryptoErrorCode::kOperationFailed, "HASH_FINALIZE response has invalid parameter type")};
    }

    const auto& hash_data = hash_result.value();
    auto bytes_to_copy = std::min(hash_data.size(), output.size());
    std::memcpy(output.data(), hash_data.data(), bytes_to_copy);

    // TODO: Consider if we should just abort here and not write anything to the output buffer
    // We may also be able to get the required out size as soon as we have created the ctx
    // at least a sub-set of operations / algorithms.
    if (bytes_to_copy < hash_data.size())
    {
        score::mw::log::LogError()
            << "[API][HashContextImpl] ERROR: Output buffer too small for full hash, truncated copy performed";
        return score::Result<std::size_t>{
            score::unexpect,
            MakeError(CryptoErrorCode::kInsufficientBufferSize,
                      "ERROR: Output buffer too small for full hash, truncated copy performed")};
    }

    return bytes_to_copy;
}

score::Result<std::size_t> HashContextImpl::SingleShot(score::cpp::span<const uint8_t> input,
                                                       score::cpp::span<uint8_t> output)
{
    auto control_req_result = proto::ControlRequestBuilder()
                                  .forDataNodeId(m_context_id)
                                  .operation({actors::OP_ACTOR_HASH_HANDLER, hash_ops::HASH_SS})
                                  .with_in_data_buffer(input)
                                  .build();

    if (!control_req_result.has_value())
    {
        score::mw::log::LogError() << "[API][HashContextImpl] ERROR: Failed to build HASH_SS request";
        return score::Result<std::size_t>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build HASH_SS request")};
    }

    auto control_response_res = m_connection->SendRequest(control_req_result.value());

    // Validate HASH_SS response
    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation({actors::OP_ACTOR_HASH_HANDLER, hash_ops::HASH_SS}).expectSuccess();

    if (!validator.isValid())
    {
        score::mw::log::LogError() << "[API][HashContextImpl] ERROR:" << validator.getError();
        return score::Result<std::size_t>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "HASH_SS daemon response invalid")};
    }

    auto hash_result = validator.getParameterAt<proto::DataBufferReturn>(0, 0);
    if (!hash_result.has_value())
    {
        score::mw::log::LogError() << "[API][HashContextImpl] ERROR: HASH_SS response has invalid parameter type";
        return score::Result<std::size_t>{
            score::unexpect,
            MakeError(CryptoErrorCode::kOperationFailed, "HASH_SS response has invalid parameter type")};
    }

    const auto& hash_data = hash_result.value();
    auto bytes_to_copy = std::min(hash_data.size(), output.size());
    std::memcpy(output.data(), hash_data.data(), bytes_to_copy);

    // TODO: Consider if we should just abort here and not write anything to the output buffer
    // We may also be able to get the required out size as soon as we have created the ctx
    // at least a sub-set of operations / algorithms.
    if (bytes_to_copy < hash_data.size())
    {
        score::mw::log::LogError()
            << "[API][HashContextImpl] ERROR: Output buffer too small for full hash, truncated copy performed";
        return score::Result<std::size_t>{
            score::unexpect,
            MakeError(CryptoErrorCode::kInsufficientBufferSize,
                      "ERROR: Output buffer too small for full hash, truncated copy performed")};
    }

    return bytes_to_copy;
}

score::Result<std::monostate> HashContextImpl::Reset()
{
    auto control_req_result = proto::ControlRequestBuilder()
                                  .forDataNodeId(m_context_id)
                                  .operation({actors::OP_ACTOR_HASH_HANDLER, hash_ops::HASH_RESET})
                                  .build();
    if (!control_req_result.has_value())
    {
        score::mw::log::LogError() << "[API][HashContextImpl] ERROR: Failed to build HASH_RESET request";
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
        score::mw::log::LogError() << "[API][HashContextImpl] ERROR:" << validator.getError();
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "HASH_RESET daemon response invalid")};
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
}  // namespace mw
}  // namespace score

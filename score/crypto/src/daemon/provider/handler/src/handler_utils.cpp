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

#include "handler_utils.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"

namespace score
{
namespace crypto
{
namespace daemon
{
namespace provider
{
namespace handler
{
namespace handler_utils
{

Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
ExtractOutputBufferData(common::RequestParameter& userData, uint8_t*& buffer, size_t& size) noexcept
{
    if (auto bufferPtr = std::get_if<score::cpp::span<uint8_t>>(&userData))
    {
        if (bufferPtr->data() == nullptr || bufferPtr->empty())
        {
            buffer = nullptr;
            size = 0;
            return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInsufficientBufferSize);
        }

        buffer = bufferPtr->data();
        size = bufferPtr->size();
        return std::monostate{};
    }

    // Unsupported type in variant (e.g., CString, or integral types as output buffers)
    buffer = nullptr;
    size = 0;
    return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidDataType);
}

Expected<common::StreamOperationState, score::crypto::daemon::common::DaemonErrorCode> ValidateStreamOperationSequence(
    common::StreamOperationState currentState,
    StreamOperation streamOperation) noexcept
{
    switch (streamOperation)
    {
        case StreamOperation::kInit:
            // Init is allowed from any state; transitions to STREAM_INITIALIZED
            return common::StreamOperationState::STREAM_INITIALIZED;

        case StreamOperation::kUpdate:
            if (currentState == common::StreamOperationState::STREAM_INITIALIZED ||
                currentState == common::StreamOperationState::STREAM_ACTIVE)
            {
                return common::StreamOperationState::STREAM_ACTIVE;
            }
            return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidStreamOperation);

        case StreamOperation::kFinalize:
            if (currentState != common::StreamOperationState::STREAM_ACTIVE)
            {
                return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidStreamOperation);
            }
            return common::StreamOperationState::IDLE;
    }

    // Unreachable with a well-formed enum; satisfies compilers that warn on missing return
    return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
}

}  // namespace handler_utils

}  // namespace handler
}  // namespace provider
}  // namespace daemon
}  // namespace crypto
}  // namespace score

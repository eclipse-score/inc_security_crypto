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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_HANDLER_SRC_HANDLER_UTILS_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_HANDLER_SRC_HANDLER_UTILS_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <type_traits>
#include <variant>

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

/**
 * @brief Utility functions for cryptographic handlers
 *
 * This namespace provides common validation and data extraction functions
 * that can be reused across different handler implementations (Hash, MAC, Sign, etc.)
 */
namespace handler_utils
{

namespace detail
{

template <typename T>
struct SpanTraits
{
    using SpanType = score::cpp::span<T>;
    using ParamType =
        std::conditional_t<std::is_const_v<T>, const common::RequestParameter&, common::RequestParameter&>;
};

}  // namespace detail

/**
 * @brief Extract and validate a buffer span from a RequestParameter.
 *
 * @tparam T The element type of the span to extract (const uint8_t for input,
 *           uint8_t for output). Parameter constness is deduced from T.
 * @param param The RequestParameter variant expected to hold a span<T>.
 * @return The extracted span on success, or an error code otherwise.
 *
 * @retval score::cpp::span<T> Span successfully extracted.
 * @retval score::crypto::daemon::common::DaemonErrorCode::kInvalidDataType Parameter is not the requested span type.
 * @retval score::crypto::daemon::common::DaemonErrorCode::kInsufficientBufferSize Null data or zero size.
 */
template <typename T>
[[nodiscard]] Expected<typename detail::SpanTraits<T>::SpanType, ::score::crypto::daemon::common::DaemonErrorCode>
CheckAndGetSpan(typename detail::SpanTraits<T>::ParamType param) noexcept
{
    using SpanType = typename detail::SpanTraits<T>::SpanType;
    auto* span = std::get_if<SpanType>(&param);
    if (span == nullptr)
    {
        return make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInvalidDataType);
    }
    if (span->data() == nullptr || span->size() == 0U)
    {
        return make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInsufficientBufferSize);
    }
    return *span;
}

/**
 * @brief Streaming operation kind used to drive the stream state machine.
 *
 * Maps a concrete operation (init/update/finalize) onto a state transition in
 * ValidateStreamOperationSequence().
 */
enum class StreamOperation : std::uint8_t
{
    kInit,      ///< Initialize (or restart) a streaming operation.
    kUpdate,    ///< Feed additional data into an active stream.
    kFinalize,  ///< Complete the stream and produce the final result.
};

/**
 * @brief Validate a streaming operation and return the resulting next state.
 *
 * Enforces the stream state machine:
 * - IDLE --(kInit)--> STREAM_INITIALIZED
 * - STREAM_INITIALIZED --(kInit)--> STREAM_INITIALIZED (restart)
 * - STREAM_INITIALIZED --(kUpdate)--> STREAM_ACTIVE
 * - STREAM_ACTIVE --(kUpdate)--> STREAM_ACTIVE
 * - STREAM_ACTIVE --(kInit)--> STREAM_INITIALIZED (restart)
 * - STREAM_ACTIVE --(kFinalize)--> IDLE
 *
 * @param currentState The current operation state (IDLE, STREAM_INITIALIZED, or STREAM_ACTIVE)
 * @param streamOperation The streaming operation being requested
 * @return Expected containing the next StreamOperationState on success, or DaemonErrorCode on failure
 *
 * @retval StreamOperationState Transition valid; value is the resulting state
 * @retval kInvalidStreamOperation UPDATE/FINALIZE attempted from invalid state
 */
[[nodiscard]] Expected<common::StreamOperationState, ::score::crypto::daemon::common::DaemonErrorCode>
ValidateStreamOperationSequence(common::StreamOperationState currentState, StreamOperation streamOperation) noexcept;

}  // namespace handler_utils

}  // namespace handler
}  // namespace provider
}  // namespace daemon
}  // namespace crypto
}  // namespace score

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_HANDLER_SRC_HANDLER_UTILS_HPP

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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_HANDLER_HANDLER_UTILS_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_HANDLER_HANDLER_UTILS_HPP

#include "score/crypto/common/types.hpp"
#include "score/crypto/daemon/common/daemon_error.hpp"
#include "score/crypto/daemon/common/types.hpp"
#include <cstddef>
#include <cstdint>
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

/**
 * @brief Extract buffer data from RequestParameter structure
 *
 * Supports extraction of data from virtual mapped memory regions.
 * Currently assumes VIR_MAPPED data type, but can be extended for other types.
 *
 * @param userData The RequestParameter structure containing the buffer information
 * @param buffer Output pointer to the extracted buffer
 * @param size Output parameter for the buffer size in bytes
 * @return std::monostate on success, error code otherwise
 *
 * @retval std::monostate Buffer successfully extracted
 * @retval score::crypto::daemon::common::DaemonErrorCode::kInsufficientBufferSize Invalid buffer address or zero size
 * @retval score::crypto::daemon::common::DaemonErrorCode::kInvalidDataType) Unsupported data type
 */
[[nodiscard]] Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode>
ExtractBufferData(const common::RequestParameter& userData, const uint8_t*& buffer, size_t& size) noexcept;

/**
 * @brief Extract non-const buffer data from RequestParameter structure
 *
 * Similar to ExtractBufferData but returns non-const pointer for output buffers.
 * Supports extraction of data from virtual mapped memory regions.
 *
 * @param userData The RequestParameter structure containing the buffer information
 * @param buffer Output pointer to the extracted buffer (non-const)
 * @param size Output parameter for the buffer size in bytes
 * @return std::monostate on success, error code otherwise
 *
 * @retval std::monostate Buffer successfully extracted
 * @retval score::crypto::daemon::common::DaemonErrorCode::kInsufficientBufferSize Invalid buffer address or zero size
 * @retval score::crypto::daemon::common::DaemonErrorCode::kInvalidDataType) Unsupported data type
 */
[[nodiscard]] Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode>
ExtractOutputBufferData(common::RequestParameter& userData, uint8_t*& buffer, size_t& size) noexcept;

/// @brief Type-safe identifiers for streaming operation phases.
///
/// Used by ValidateStreamOperationSequence to enforce the stream state machine
enum class StreamOperation : std::uint8_t
{
    kInit = 0,      ///< Initialize or restart the streaming operation
    kUpdate = 1,    ///< Feed data into the active stream
    kFinalize = 2,  ///< Finalize the stream and produce output
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

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_HANDLER_HANDLER_UTILS_HPP

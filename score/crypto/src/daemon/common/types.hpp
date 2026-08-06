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

#ifndef SCORE_CRYPTO_SRC_DAEMON_COMMON_TYPES_HPP
#define SCORE_CRYPTO_SRC_DAEMON_COMMON_TYPES_HPP

#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>
#include <vector>

#include "score/span.hpp"

namespace score::crypto::daemon::common
{

using HandlerId = std::string;
using AlgorithmId = std::string;
// TODO: MediatorId shall use numeric type
using MediatorId = std::string;

// ============================================================================
// Provider Identity Types
// ============================================================================
// ProviderName: Human-readable identifier used at configuration and setup time
using ProviderName = std::string;

// ProviderId: Numeric identifier assigned at runtime by ProviderManager
using ProviderId = std::uint16_t;

constexpr ProviderId kInvalidProviderId = std::numeric_limits<ProviderId>::max();

using OperationActor = uint16_t;
using OperationAction = uint16_t;

// Starting point for custom actors
inline constexpr OperationActor CUSTOM_ACTOR_START = 1 << (std::numeric_limits<OperationActor>::digits - 1);

struct OperationIdentifier
{
    OperationActor operationActor{0};
    OperationAction operationAction{0};
};

// ============================================================================
// Non-owning buffer types for zero-copy parameter passing
// ============================================================================
struct NoParam
{
};

// ============================================================================
// Shared Memory parameter types for SHM request handler
// ============================================================================

enum class ShmDirection : std::uint8_t
{
    In = 0,     ///< Daemon reads from this region
    InOut = 1,  ///< Daemon both reads and writes
};

/// @brief Backend-agnostic shared memory parameter for crypto operations.
/// The daemon resolves node_id via its internal region map
struct DataShm
{
    std::uint64_t node_id{0};  ///< Daemon-assigned DataNodeId — opaque region handle.
    std::size_t offset{0};     ///< Byte offset within the region.
    std::size_t size{0};       ///< Number of bytes to access.
    ShmDirection direction{ShmDirection::In};
};
// ============================================================================
// Owning buffer types
// ============================================================================

/// Owning buffers - These needs to be here to be able to define a common
/// parameter set for both the Lib and Daemon and thus make the std::variants
/// directly compatible.
// /Ideally, we do not make use of these in the daemon
/// to avoid unnecessary copies.
/// On the Lib side, we MUST use these for the responsess
/// since otherwise, we are able to properly control the lifetime of the returned data
/// The IPC shall only return owning types for Lib responses
using OwnedString = std::string;
using OwnedBuffer = std::vector<std::uint8_t>;

// ============================================================================
// Unified Parameter Variants
// ============================================================================

/// Input parameter variant: always non-owning (borrows from caller or IPC buffer)
using RequestParameter = std::variant<NoParam,
                                      bool,
                                      std::uint8_t,
                                      std::uint16_t,
                                      std::uint32_t,
                                      std::uint64_t,
                                      score::cpp::span<const uint8_t>,  // input buffer
                                      score::cpp::span<uint8_t>,        // output buffer
                                      DataShm,
                                      std::string_view>;

/// Output parameter variant:
// - Always owning on the lib side, since we need to take ownership when returning from the IPC
// - Owning and non-owning on daemon side, depending on the usage
//   - Requests are non-owning. (IPC owns the data)
//   - Responses may be owning, if buffers were created during the operation
using ResponseParameter = std::variant<NoParam,
                                       bool,
                                       std::uint8_t,
                                       std::uint16_t,
                                       std::uint32_t,
                                       std::uint64_t,
                                       score::cpp::span<const uint8_t>,  // buffer with data to be returned
                                       OwnedString,
                                       OwnedBuffer>;

// ============================================================================
// Unified Operation Request/Response
// ============================================================================
using RequestParameters = std::vector<RequestParameter>;
using ResponseParameters = std::vector<ResponseParameter>;

// Stream operation state for synchronous flow enforcement
enum class StreamOperationState : std::uint8_t
{
    IDLE = 0,                // No operation in progress
    STREAM_INITIALIZED = 1,  // Init operation completed, stream ready for Update
    STREAM_ACTIVE = 2,       // Stream active, accepting Update or Finalize
};

/**
 * @brief Functional categories of crypto providers
 * Used to categorize providers by their purpose/capability
 */
enum class CryptoProviderType : std::uint8_t
{
    DEFAULT,      ///< Default provider for general operations
    HARDWARE,     ///< Hardware-based crypto provider (TPM, HSM)
    SOFTWARE,     ///< Software-based crypto provider
    SPECIALIZED,  ///< Specialized provider for specific operations
};

inline CryptoProviderType CryptoProviderTypeFromString(const std::string& typeStr)
{
    if (typeStr == "DEFAULT")
    {
        return CryptoProviderType::DEFAULT;
    }
    else if (typeStr == "HARDWARE")
    {
        return CryptoProviderType::HARDWARE;
    }
    else if (typeStr == "SOFTWARE")
    {
        return CryptoProviderType::SOFTWARE;
    }
    else if (typeStr == "SPECIALIZED")
    {
        return CryptoProviderType::SPECIALIZED;
    }
    else
    {
        return CryptoProviderType::SPECIALIZED;  // Default to SPECIALIZED for unknown types
    }
}

}  // namespace score::crypto::daemon::common

/**
 * @brief Hash specialization for CryptoProviderType enum to enable use in
 * unordered_map
 */
namespace std
{
template <>
struct hash<score::crypto::daemon::common::CryptoProviderType>
{
    size_t operator()(score::crypto::daemon::common::CryptoProviderType type) const noexcept
    {
        return std::hash<int>()(static_cast<int>(type));
    }
};
}  // namespace std

#endif  // SCORE_CRYPTO_SRC_DAEMON_COMMON_TYPES_HPP

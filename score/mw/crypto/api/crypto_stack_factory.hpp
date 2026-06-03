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

#ifndef SCORE_MW_CRYPTO_API_CRYPTO_STACK_FACTORY_HPP
#define SCORE_MW_CRYPTO_API_CRYPTO_STACK_FACTORY_HPP

#include "score/mw/crypto/api/i_crypto_stack.hpp"
#include "score/result/result.h"

#include <chrono>
#include <optional>
#include <string>
#include <string_view>

namespace score
{
namespace mw
{
namespace crypto
{

/// @brief Configuration builder for creating a crypto stack instance.
struct CryptoStackConfig
{
    // TODO: Will hide this information in this future, via mw::com
    /// @brief Daemon endpoint URI (required).
    /// Examples: "unix:///tmp/crypto_daemon.sock"
    std::string connection_endpoint{};

    /// @brief Default per-IPC-call timeout for all operations on this stack.
    ///
    /// Each IPC call (Init, Update, Finalize, ResolveResource, etc.) must
    /// complete within this deadline. For streaming operations, the timeout
    /// applies to each individual call, not the entire sequence.
    ///
    /// When std::nullopt (default), the daemon applies its own default
    ///
    /// Per-context overrides are available via BaseContextConfig::operation_timeout.
    std::optional<std::chrono::milliseconds> default_operation_timeout{std::nullopt};

    /// @brief Set connection endpoint
    CryptoStackConfig& SetConnectionEndpoint(std::string_view endpoint)
    {
        connection_endpoint = std::string{endpoint};
        return *this;
    }

    /// @brief Sets the stack-wide default operation timeout.
    /// @param timeout Maximum duration for any single IPC call.
    ///        Operations exceeding this return kOperationTimedOut.
    CryptoStackConfig& SetDefaultOperationTimeout(std::chrono::milliseconds timeout)
    {
        default_operation_timeout = timeout;
        return *this;
    }

    // Future extensible fields:
    // std::optional<std::chrono::milliseconds> connection_timeout{std::nullopt};
    // std::optional<std::string> tls_ca_cert_path{std::nullopt};
    // std::optional<uint32_t> max_retry_attempts{std::nullopt};
    // std::optional<std::string> application_identity_hint{std::nullopt};
};

/// @brief Creates a new crypto stack.
///
/// Top-level entry point to the crypto middleware. Each call returns a
/// new independent stack handle. Multiple stacks within the same process
/// share the internally managed daemon connection. Contexts and allocators
/// obtained from the stack have independent lifetimes and may outlive it.
///
/// @param config Stack configuration with at minimum a connection endpoint
/// @return Unique pointer to the created stack, or error on connection failure
score::Result<ICryptoStack::Uptr> CreateCryptoStack(const CryptoStackConfig& config);

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_CRYPTO_STACK_FACTORY_HPP

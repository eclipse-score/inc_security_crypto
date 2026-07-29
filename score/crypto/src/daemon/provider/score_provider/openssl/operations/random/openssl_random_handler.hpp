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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_RANDOM_OPENSSL_RANDOM_HANDLER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_RANDOM_OPENSSL_RANDOM_HANDLER_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/handler/handler_init_params.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/random/random_executor.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/random/score_random_handler.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{

/// @brief OpenSSL random number generator handler.
///
/// Draws from OpenSSL's public RNG (RAND_bytes), which is a NIST SP 800-90A
/// CTR-DRBG seeded from the operating system entropy source and reseeded
/// automatically. Seed() feeds additional entropy via RAND_add without
/// increasing the assessed entropy estimate, so caller-supplied material can
/// never weaken the pool.
///
/// Accepted algorithm identifiers are the empty string (provider default) and
/// "CTR-DRBG"; anything else is rejected so that a caller asking for a specific
/// generator never silently gets a different one.
class OpenSslRandomHandler final
    : public ::score::crypto::daemon::provider::score_provider::operations::random::ScoreRandomHandler
{
  public:
    using Sptr = std::shared_ptr<OpenSslRandomHandler>;

    explicit OpenSslRandomHandler(std::unique_ptr<operations::random::RandomExecutor> executor,
                                  const common::AlgorithmId& algorithm);
    ~OpenSslRandomHandler() override = default;

    OpenSslRandomHandler(const OpenSslRandomHandler&) = delete;
    OpenSslRandomHandler& operator=(const OpenSslRandomHandler&) = delete;
    OpenSslRandomHandler(OpenSslRandomHandler&&) = delete;
    OpenSslRandomHandler& operator=(OpenSslRandomHandler&&) = delete;

    // -----------------------------------------------------------------------
    // ScoreRandomHandler interface
    // -----------------------------------------------------------------------

    [[nodiscard]] ::score::crypto::Expected<std::size_t, ::score::crypto::daemon::common::DaemonErrorCode>
    GenerateRandom(score::cpp::span<std::uint8_t> output) override;

    [[nodiscard]] ::score::crypto::Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode>
    SeedRandom(const common::RequestParameter& seed) override;

    /// @brief Check if the given RNG algorithm identifier is supported.
    [[nodiscard]] static bool IsAlgorithmSupported(const common::AlgorithmId& algorithm) noexcept;

  private:
    static constexpr std::string_view LOG_PREFIX = "[OPENSSL_RANDOM_HANDLER]";
};

}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_RANDOM_OPENSSL_RANDOM_HANDLER_HPP

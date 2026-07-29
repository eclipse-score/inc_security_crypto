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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_RANDOM_SCORE_RANDOM_HANDLER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_RANDOM_SCORE_RANDOM_HANDLER_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/handler/i_handler.hpp"

#include "score/span.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>

namespace score::crypto::daemon::provider::score_provider::operations::random
{

class RandomExecutor;

/// @brief Abstract base handler for random number generation under the score
///        interface family.
///
/// Unlike the hash / MAC / cipher handlers this context is not streaming: there
/// is no state machine, and Generate() / Seed() are valid at any time. The
/// executor therefore only demultiplexes the two operations and marshals buffers.
class ScoreRandomHandler : public handler::Handler
{
  public:
    using Sptr = std::shared_ptr<ScoreRandomHandler>;

    ScoreRandomHandler() = delete;

    /// @param executor   Random executor injected by the handler factory.
    /// @param algorithm  RNG algorithm identifier; empty selects the provider default.
    explicit ScoreRandomHandler(std::unique_ptr<RandomExecutor> executor, const common::AlgorithmId& algorithm);

    ~ScoreRandomHandler() override = default;

    // -----------------------------------------------------------------------
    // Handler interface
    // -----------------------------------------------------------------------

    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> Execute(
        const common::OperationIdentifier& operationId,
        common::RequestParameters& request) override;

    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> InitializeContext(
        const handler::InitializationParams& init_params) override;

    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> Reset() override;

    [[nodiscard]] const common::AlgorithmId& GetAlgorithm() const noexcept
    {
        return m_algorithm;
    }

    /// @brief Upper bound on bytes served by a single Generate() call.
    ///
    /// Bounds the daemon-side allocation a client can trigger with one request.
    static constexpr std::size_t kMaxGenerateBytes = 64U * 1024U;

    // -----------------------------------------------------------------------
    // Typed random operations — override in concrete provider handlers
    // -----------------------------------------------------------------------

    /// @brief Fill @p output with cryptographically secure random bytes.
    /// @param output Caller-provided buffer, already resolved from shared memory.
    /// @return Bytes written, always the full length of @p output on success.
    [[nodiscard]] virtual Expected<std::size_t, common::DaemonErrorCode> GenerateRandom(
        score::cpp::span<std::uint8_t> output);

    /// @brief Mix additional entropy into the generator state.
    /// @note Providers without an externally seedable source report success
    ///       without changing any state.
    [[nodiscard]] virtual Expected<std::monostate, common::DaemonErrorCode> SeedRandom(
        const common::RequestParameter& seed);

  protected:
    common::AlgorithmId m_algorithm;

  private:
    std::unique_ptr<RandomExecutor> m_executor;
};

}  // namespace score::crypto::daemon::provider::score_provider::operations::random

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_RANDOM_SCORE_RANDOM_HANDLER_HPP

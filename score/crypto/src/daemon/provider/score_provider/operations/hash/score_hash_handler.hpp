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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_HASH_SCORE_HASH_HANDLER_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_HASH_SCORE_HASH_HANDLER_HPP

#include "score/crypto/common/types.hpp"
#include "score/crypto/daemon/common/algorithm_info.hpp"
#include "score/crypto/daemon/common/daemon_error.hpp"
#include "score/crypto/daemon/common/types.hpp"
#include "score/crypto/daemon/provider/handler/i_handler.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>

namespace score::crypto::daemon::provider::score_provider::operations::hash
{

class HashExecutor;

/// @brief Abstract base handler for hash operations under the score interface family.
///
/// Implements the daemon's Handler interface by delegating Execute() to the
/// injected HashExecutor. Concrete score-interface providers (e.g. OpenSSL)
/// inherit from this class and override the typed hash methods.
///
/// Typed methods default to kUnsupportedOperation so that a partially-implemented
/// provider compiles and returns a clear error at runtime.
///
/// State management (algorithm, stream operation state) is centralised here.
class ScoreHashHandler : public handler::Handler
{
  public:
    using Sptr = std::shared_ptr<ScoreHashHandler>;

    ScoreHashHandler() = delete;

    /// @param executor   Hash executor injected by the handler factory.
    /// @param algorithm  Algorithm identifier (e.g. "SHA256").
    explicit ScoreHashHandler(std::unique_ptr<HashExecutor> executor, const common::AlgorithmId& algorithm);

    ~ScoreHashHandler() override = default;

    // -----------------------------------------------------------------------
    // Handler interface (final — orchestration is fixed in the base)
    // -----------------------------------------------------------------------

    /// Delegates to the injected executor.
    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> Execute(
        const common::OperationIdentifier& operationId,
        common::RequestParameters& request) override;

    /// Validates algorithm and resets state to IDLE.
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> InitializeContext(
        const handler::InitializationParams& init_params) override;

    /// Resets intermediate state back to IDLE.
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> Reset() override;

    // -----------------------------------------------------------------------
    // Stream state management
    // -----------------------------------------------------------------------

    [[nodiscard]] common::StreamOperationState GetOperationState() const noexcept
    {
        return m_state;
    }

    void SetOperationState(common::StreamOperationState state) noexcept
    {
        m_state = state;
    }

    [[nodiscard]] const common::AlgorithmId& GetAlgorithm() const noexcept
    {
        return m_algorithm;
    }

    // -----------------------------------------------------------------------
    // Typed hash operations — override in concrete provider handlers
    // -----------------------------------------------------------------------

    /// @brief Initialize a hash operation on an existing context.
    [[nodiscard]] virtual Expected<std::monostate, common::DaemonErrorCode> InitHash(
        const std::optional<common::RequestParameter> initialDataOrIV);

    /// @brief Add data to the active hash stream.
    [[nodiscard]] virtual Expected<std::monostate, common::DaemonErrorCode> UpdateHash(
        const common::RequestParameter& dataToHash);

    /// @brief Finalize the hash and produce the digest.
    [[nodiscard]] virtual Expected<common::ResponseParameters, common::DaemonErrorCode> FinalizeHash(
        std::optional<common::RequestParameter> hashOutput,
        const std::optional<common::RequestParameter> finalDataToHash);

    /// @brief Perform single-shot hash without streaming.
    [[nodiscard]] virtual Expected<common::ResponseParameters, common::DaemonErrorCode> SingleShotHash(
        const common::RequestParameter& dataToHash,
        std::optional<common::RequestParameter> outputHash,
        std::optional<common::RequestParameter> iv);

    /// @brief Get the digest size for the current algorithm.
    [[nodiscard]] virtual Expected<common::ResponseParameters, common::DaemonErrorCode> GetDigestSize() const;

  protected:
    common::AlgorithmId m_algorithm;
    common::StreamOperationState m_state{common::StreamOperationState::IDLE};

  private:
    std::unique_ptr<HashExecutor> m_executor;
};

}  // namespace score::crypto::daemon::provider::score_provider::operations::hash

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_HASH_SCORE_HASH_HANDLER_HPP

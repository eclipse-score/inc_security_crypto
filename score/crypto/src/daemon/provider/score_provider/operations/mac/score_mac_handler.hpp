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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_MAC_SCORE_MAC_HANDLER_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_MAC_SCORE_MAC_HANDLER_HPP

#include "score/crypto/common/types.hpp"
#include "score/crypto/daemon/common/daemon_error.hpp"
#include "score/crypto/daemon/common/types.hpp"
#include "score/crypto/daemon/provider/handler/i_handler.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>

namespace score::crypto::daemon::provider::score_provider::operations::mac
{

class MacExecutor;

/// @brief Abstract base handler for MAC operations under the score interface family.
///
/// Implements the daemon's Handler interface by delegating Execute() to the
/// injected MacExecutor. Concrete score-interface providers (e.g. OpenSSL)
/// inherit from this class and override the typed MAC methods.
///
/// Typed methods default to kUnsupportedOperation so that a partially-implemented
/// provider compiles and returns a clear error at runtime.
///
/// Key binding is performed via InitializeContext(): the mediator sets
/// bound_key_handler before calling InitializeContext(), which the concrete
/// handler uses to bind the key.
class ScoreMacHandler : public handler::Handler
{
  public:
    using Sptr = std::shared_ptr<ScoreMacHandler>;

    ScoreMacHandler() = delete;

    /// @param executor   MAC executor injected by the handler factory.
    /// @param algorithm  Algorithm identifier (e.g. "HMAC-SHA256").
    explicit ScoreMacHandler(std::unique_ptr<MacExecutor> executor, const common::AlgorithmId& algorithm);

    ~ScoreMacHandler() override = default;

    // -----------------------------------------------------------------------
    // Handler interface
    // -----------------------------------------------------------------------

    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> Execute(
        const common::OperationIdentifier& operationId,
        common::RequestParameters& request) override;

    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> InitializeContext(
        const handler::InitializationParams& init_params) override;

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
    // Typed MAC operations — override in concrete provider handlers
    // -----------------------------------------------------------------------

    /// @brief Get the MAC tag size for the current algorithm.
    [[nodiscard]] virtual std::size_t GetMacSize() const noexcept;

    /// @brief Initialize the MAC stream context with the cached key.
    [[nodiscard]] virtual Expected<std::monostate, common::DaemonErrorCode> InitMac(
        const std::optional<common::RequestParameter> initialDataOrIV);

    /// @brief Add data to the active MAC stream.
    [[nodiscard]] virtual Expected<std::monostate, common::DaemonErrorCode> UpdateMac(
        const common::RequestParameter& dataToMac);

    /// @brief Finalize the MAC and produce the tag.
    [[nodiscard]] virtual Expected<common::ResponseParameters, common::DaemonErrorCode> FinalizeMac(
        std::optional<common::RequestParameter> macOutput,
        const std::optional<common::RequestParameter> finalDataToMac);

    /// @brief Verify a MAC tag using constant-time comparison.
    [[nodiscard]] virtual Expected<bool, common::DaemonErrorCode> VerifyMac(
        const common::RequestParameter& expectedTag);

  protected:
    common::AlgorithmId m_algorithm;
    common::StreamOperationState m_state{common::StreamOperationState::IDLE};

  private:
    std::unique_ptr<MacExecutor> m_executor;
};

}  // namespace score::crypto::daemon::provider::score_provider::operations::mac

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_MAC_SCORE_MAC_HANDLER_HPP

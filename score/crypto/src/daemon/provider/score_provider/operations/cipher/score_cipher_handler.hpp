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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_CIPHER_SCORE_CIPHER_HANDLER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_CIPHER_SCORE_CIPHER_HANDLER_HPP

#include "score/crypto/src/api/common/types.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/handler/i_handler.hpp"

#include "score/span.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>

namespace score::crypto::daemon::provider::score_provider::operations::cipher
{

class CipherExecutor;

/// @brief Abstract base handler for symmetric cipher operations under the score
///        interface family.
///
/// Mirrors ScoreMacHandler: the daemon's Handler::Execute() is delegated to the
/// injected CipherExecutor, which validates the stream state machine and routes
/// to the typed methods below. Concrete score-interface providers (e.g. OpenSSL)
/// inherit and override those typed methods.
///
/// Typed methods default to kUnsupportedOperation so that a partially-implemented
/// provider still compiles and returns a clear error at runtime.
///
/// The cipher direction is fixed for the lifetime of the context: it is read from
/// CTX_CREATE param[4] in InitializeContext() and never changes afterwards, so a
/// context created for encryption can never accidentally decrypt.
class ScoreCipherHandler : public handler::Handler
{
  public:
    using Sptr = std::shared_ptr<ScoreCipherHandler>;

    ScoreCipherHandler() = delete;

    /// @param executor   Cipher executor injected by the handler factory.
    /// @param algorithm  Algorithm identifier (e.g. "AES-256-CBC").
    explicit ScoreCipherHandler(std::unique_ptr<CipherExecutor> executor, const common::AlgorithmId& algorithm);

    ~ScoreCipherHandler() override = default;

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

    [[nodiscard]] score::crypto::CipherDirection GetDirection() const noexcept
    {
        return m_direction;
    }

    // -----------------------------------------------------------------------
    // Typed cipher operations — override in concrete provider handlers
    // -----------------------------------------------------------------------

    /// @brief Cipher block size in bytes (1 for stream modes such as CTR).
    [[nodiscard]] virtual std::size_t GetBlockSize() const noexcept;

    /// @brief Required IV / nonce length in bytes (0 for ECB).
    [[nodiscard]] virtual std::size_t GetIvSize() const noexcept;

    /// @brief Initialize the cipher stream with the bound key and the given IV.
    /// @param iv Absent for IV-less modes; implementations reject a missing IV
    ///           when GetIvSize() is non-zero.
    [[nodiscard]] virtual Expected<std::monostate, common::DaemonErrorCode> InitCipher(
        std::optional<common::RequestParameter> iv);

    /// @brief Process one input chunk into the caller's output buffer.
    /// @param output Caller-provided buffer, already resolved from shared memory.
    /// @return Bytes written, which may legitimately be zero while a block cipher
    ///         buffers a partial block.
    [[nodiscard]] virtual Expected<std::size_t, common::DaemonErrorCode> UpdateCipher(
        const common::RequestParameter& input,
        score::cpp::span<std::uint8_t> output);

    /// @brief Finish the stream, writing any trailing bytes (final padded block).
    /// @return Bytes written, zero for stream modes.
    [[nodiscard]] virtual Expected<std::size_t, common::DaemonErrorCode> FinalizeCipher(
        score::cpp::span<std::uint8_t> output);

  protected:
    common::AlgorithmId m_algorithm;
    common::StreamOperationState m_state{common::StreamOperationState::IDLE};
    score::crypto::CipherDirection m_direction{score::crypto::CipherDirection::kEncrypt};

    /// @brief Reads the cipher direction from CTX_CREATE param[4].
    ///
    /// Leaves m_direction untouched when the parameter is absent or has the
    /// wrong type, so the kEncrypt default applies.
    void ExtractDirection(const handler::InitializationParams& init_params) noexcept;

  private:
    std::unique_ptr<CipherExecutor> m_executor;
};

}  // namespace score::crypto::daemon::provider::score_provider::operations::cipher

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_CIPHER_SCORE_CIPHER_HANDLER_HPP

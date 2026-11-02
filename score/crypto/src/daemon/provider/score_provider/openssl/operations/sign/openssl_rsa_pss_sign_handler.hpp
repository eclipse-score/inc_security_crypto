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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_SIGN_OPENSSL_RSA_PSS_SIGN_HANDLER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_SIGN_OPENSSL_RSA_PSS_SIGN_HANDLER_HPP

#include "score/crypto/src/daemon/provider/score_provider/openssl/detail/signature_common.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/sign/score_sign_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/sign/sign_executor.hpp"
#include "score/span.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <variant>
#include <vector>

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{

/// @brief OpenSSL RSA-PSS signature generation handler.
class OpenSslRsaPssSignHandler final : public operations::sign::ScoreSignHandler
{
  public:
    explicit OpenSslRsaPssSignHandler(std::unique_ptr<operations::sign::SignExecutor> executor,
                                      const common::AlgorithmId& algorithm);
    ~OpenSslRsaPssSignHandler() override;
    OpenSslRsaPssSignHandler(const OpenSslRsaPssSignHandler&) = delete;
    OpenSslRsaPssSignHandler& operator=(const OpenSslRsaPssSignHandler&) = delete;

    Expected<std::monostate, common::DaemonErrorCode> InitializeContext(
        const ::score::crypto::daemon::provider::handler::InitializationParams&) override;
    Expected<std::monostate, common::DaemonErrorCode> Reset() override;
    std::size_t GetSignatureSize() const noexcept override;
    Expected<std::monostate, common::DaemonErrorCode> InitSign() override;
    Expected<std::monostate, common::DaemonErrorCode> UpdateSign(score::cpp::span<const std::uint8_t>) override;
    Expected<std::size_t, common::DaemonErrorCode> FinalizeSign(score::cpp::span<std::uint8_t>) override;
    /// @brief Signs in one call. Message mode uses EVP_DigestSign; prehashed mode
    ///        uses EVP_PKEY_sign and requires the input to equal the digest size.
    /// @param data Message or precomputed digest to sign.
    /// @param signature Caller-provided output signature buffer.
    /// @return Number of bytes written, or an error if signing cannot be completed.
    Expected<std::size_t, common::DaemonErrorCode> SingleShotSign(score::cpp::span<const std::uint8_t> data,
                                                                  score::cpp::span<std::uint8_t> signature) override;

    /// @brief Check if the given algorithm is supported by this handler.
    static bool IsAlgorithmSupported(const common::AlgorithmId&) noexcept;

  private:
    /// @brief Creates a fresh OpenSSL context and, in message mode, initializes
    ///        the digest-sign context and RSA-PSS parameters.
    /// @return An allocation or algorithm-initialization error when setup fails.
    Expected<std::monostate, common::DaemonErrorCode> InitializeSignContext();

    /// @brief Checks that the output buffer can hold a signature.
    /// @return The signature size, kUnsupportedAlgorithm for an unknown algorithm, or
    ///         kInsufficientBufferSize if the buffer is too small.
    Expected<std::size_t, common::DaemonErrorCode> ResolveBuffer(score::cpp::span<std::uint8_t>) const;

    signature::Stream m_stream;
    std::vector<std::uint8_t> m_buffer;
    bool m_prehashed{false};
    std::size_t m_digest_size{0U};
};

}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_SIGN_OPENSSL_RSA_PSS_SIGN_HANDLER_HPP

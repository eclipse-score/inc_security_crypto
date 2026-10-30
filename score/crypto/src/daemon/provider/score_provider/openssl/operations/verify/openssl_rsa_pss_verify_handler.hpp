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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_VERIFY_OPENSSL_RSA_PSS_VERIFY_HANDLER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_VERIFY_OPENSSL_RSA_PSS_VERIFY_HANDLER_HPP

#include "score/crypto/src/daemon/provider/score_provider/openssl/detail/signature_common.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/verify/score_verify_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/verify/verify_executor.hpp"
#include "score/span.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <variant>
#include <vector>

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{

/// @brief OpenSSL RSA-PSS signature verification handler.
class OpenSslRsaPssVerifyHandler final : public operations::verify::ScoreVerifyHandler
{
  public:
    explicit OpenSslRsaPssVerifyHandler(std::unique_ptr<operations::verify::VerifyExecutor> executor,
                                        const common::AlgorithmId& algorithm);
    ~OpenSslRsaPssVerifyHandler() override;
    OpenSslRsaPssVerifyHandler(const OpenSslRsaPssVerifyHandler&) = delete;
    OpenSslRsaPssVerifyHandler& operator=(const OpenSslRsaPssVerifyHandler&) = delete;

    Expected<std::monostate, common::DaemonErrorCode> InitializeContext(
        const ::score::crypto::daemon::provider::handler::InitializationParams&) override;
    Expected<std::monostate, common::DaemonErrorCode> Reset() override;
    std::size_t GetSignatureSize() const noexcept override;
    Expected<std::monostate, common::DaemonErrorCode> InitVerify() override;
    Expected<std::monostate, common::DaemonErrorCode> UpdateVerify(score::cpp::span<const std::uint8_t>) override;
    Expected<bool, common::DaemonErrorCode> FinalizeVerify(score::cpp::span<const std::uint8_t>) override;
    /// @brief Verifies in one call. Message mode uses EVP_DigestVerify; prehashed mode
    ///        uses EVP_PKEY_verify and requires the input to equal the digest size.
    /// @param data Message or precomputed digest to verify.
    /// @param signature Signature to verify.
    /// @return true for a valid signature, false for an invalid signature, or an error
    ///         if verification cannot be completed.
    Expected<bool, common::DaemonErrorCode> SingleShotVerify(score::cpp::span<const std::uint8_t> data,
                                                             score::cpp::span<const std::uint8_t> signature) override;

    /// @brief Check if the given algorithm is supported by this handler.
    static bool IsAlgorithmSupported(const common::AlgorithmId&) noexcept;

  private:
    /// @brief Creates a fresh OpenSSL context and, in message mode, initializes
    ///        the digest-verify context and RSA-PSS parameters.
    /// @return An allocation or algorithm-initialization error when setup fails.
    Expected<std::monostate, common::DaemonErrorCode> InitializeVerifyContext();

    /// @brief Checks that the signature length equals the RSA modulus size.
    /// @return kInvalidArgument on a length mismatch.
    Expected<std::monostate, common::DaemonErrorCode> CheckSignature(score::cpp::span<const std::uint8_t>) const;

    signature::Stream m_stream;
    std::vector<std::uint8_t> m_buffer;  ///< Accumulates prehashed input until finalization
    bool m_prehashed{false};             ///< True when the input is an already computed digest
    std::size_t m_digest_size{0U};       ///< Expected digest size in prehashed mode; 0 if unknown
};

}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_VERIFY_OPENSSL_RSA_PSS_VERIFY_HANDLER_HPP

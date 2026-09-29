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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_VERIFY_OPENSSL_ECDSA_VERIFY_HANDLER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_VERIFY_OPENSSL_ECDSA_VERIFY_HANDLER_HPP

#include "score/crypto/src/daemon/provider/score_provider/openssl/detail/ecdsa_common.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/verify/score_verify_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/verify/verify_executor.hpp"
#include "score/span.hpp"

#include <memory>
#include <string_view>

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{

/// @brief OpenSSL ECDSA signature verification handler, built on EVP_DigestVerify.
///
/// Supports ECDSA on P-256, P-384 and P-521 with the NIST-paired digest
/// (SHA-256 / SHA-384 / SHA-512), selectable through algorithm identifiers such
/// as "ECDSA-P256-SHA256".
///
/// @par Signature encoding
/// Signatures arrive in the fixed-length IEEE P1363 form r‖s and are converted
/// to DER-encoded ECDSA-Sig-Value at this boundary, which is what OpenSSL
/// consumes natively.
class OpenSslEcdsaVerifyHandler final
    : public ::score::crypto::daemon::provider::score_provider::operations::verify::ScoreVerifyHandler
{
  public:
    using Sptr = std::shared_ptr<OpenSslEcdsaVerifyHandler>;

    explicit OpenSslEcdsaVerifyHandler(
        std::unique_ptr<::score::crypto::daemon::provider::score_provider::operations::verify::VerifyExecutor> executor,
        const common::AlgorithmId& algorithm);
    ~OpenSslEcdsaVerifyHandler() override;

    OpenSslEcdsaVerifyHandler(const OpenSslEcdsaVerifyHandler&) = delete;
    OpenSslEcdsaVerifyHandler& operator=(const OpenSslEcdsaVerifyHandler&) = delete;
    OpenSslEcdsaVerifyHandler(OpenSslEcdsaVerifyHandler&&) = delete;
    OpenSslEcdsaVerifyHandler& operator=(OpenSslEcdsaVerifyHandler&&) = delete;

    // -----------------------------------------------------------------------
    // Handler interface
    // -----------------------------------------------------------------------

    [[nodiscard]] ::score::crypto::Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode>
    InitializeContext(const ::score::crypto::daemon::provider::handler::InitializationParams& init_params) override;

    [[nodiscard]] ::score::crypto::Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode> Reset()
        override;

    // -----------------------------------------------------------------------
    // ScoreVerifyHandler interface
    // -----------------------------------------------------------------------

    [[nodiscard]] ::score::crypto::Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode>
    InitVerify() override;

    [[nodiscard]] ::score::crypto::Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode>
    UpdateVerify(score::cpp::span<const std::uint8_t> data) override;

    [[nodiscard]] ::score::crypto::Expected<bool, ::score::crypto::daemon::common::DaemonErrorCode> FinalizeVerify(
        score::cpp::span<const std::uint8_t> signature) override;

    /// @brief Verifies in one call through EVP_DigestVerify, OpenSSL's one-shot
    ///        entry point.
    [[nodiscard]] ::score::crypto::Expected<bool, ::score::crypto::daemon::common::DaemonErrorCode> SingleShotVerify(
        score::cpp::span<const std::uint8_t> data,
        score::cpp::span<const std::uint8_t> signature) override;

    /// @brief Check if the given algorithm is supported by this handler.
    [[nodiscard]] static bool IsAlgorithmSupported(const common::AlgorithmId& algorithm) noexcept;

  private:
    /// @brief Resolves the caller's signature and converts it to DER.
    [[nodiscard]] ::score::crypto::Expected<common::OwnedBuffer, ::score::crypto::daemon::common::DaemonErrorCode>
    ToDer(score::cpp::span<const std::uint8_t> signature) const;

    ecdsa::Stream m_stream;

    static constexpr std::string_view LOG_PREFIX = "[OPENSSL_ECDSA_VERIFY_HANDLER]";
};

}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_VERIFY_OPENSSL_ECDSA_VERIFY_HANDLER_HPP

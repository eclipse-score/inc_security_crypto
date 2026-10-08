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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_SIGN_OPENSSL_ECDSA_SIGN_HANDLER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_SIGN_OPENSSL_ECDSA_SIGN_HANDLER_HPP

#include "score/crypto/src/daemon/provider/score_provider/openssl/detail/ecdsa_common.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/sign/score_sign_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/sign/sign_executor.hpp"

#include "score/span.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{

/// @brief OpenSSL ECDSA signature generation handler, built on EVP_DigestSign.
///
/// Supports ECDSA on P-256, P-384 and P-521 with the NIST-paired digest
/// (SHA-256 / SHA-384 / SHA-512), selectable through algorithm identifiers such
/// as "ECDSA-P256-SHA256".
///
/// @par Signature encoding
/// OpenSSL natively produces DER-encoded ECDSA-Sig-Value. This handler converts
/// to the fixed-length IEEE P1363 form r‖s at its boundary so that signatures
/// interoperate byte-for-byte with the PKCS#11 provider, which is natively
/// P1363.
class OpenSslEcdsaSignHandler final
    : public ::score::crypto::daemon::provider::score_provider::operations::sign::ScoreSignHandler
{
  public:
    using Sptr = std::shared_ptr<OpenSslEcdsaSignHandler>;

    explicit OpenSslEcdsaSignHandler(
        std::unique_ptr<::score::crypto::daemon::provider::score_provider::operations::sign::SignExecutor> executor,
        const common::AlgorithmId& algorithm);
    ~OpenSslEcdsaSignHandler() override;

    OpenSslEcdsaSignHandler(const OpenSslEcdsaSignHandler&) = delete;
    OpenSslEcdsaSignHandler& operator=(const OpenSslEcdsaSignHandler&) = delete;
    OpenSslEcdsaSignHandler(OpenSslEcdsaSignHandler&&) = delete;
    OpenSslEcdsaSignHandler& operator=(OpenSslEcdsaSignHandler&&) = delete;

    // -----------------------------------------------------------------------
    // Handler interface
    // -----------------------------------------------------------------------

    [[nodiscard]] ::score::crypto::Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode>
    InitializeContext(const ::score::crypto::daemon::provider::handler::InitializationParams& init_params) override;

    [[nodiscard]] ::score::crypto::Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode> Reset()
        override;

    // -----------------------------------------------------------------------
    // ScoreSignHandler interface
    // -----------------------------------------------------------------------

    [[nodiscard]] ::score::crypto::Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode> InitSign()
        override;

    [[nodiscard]] ::score::crypto::Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode>
    UpdateSign(score::cpp::span<const std::uint8_t> data) override;

    [[nodiscard]] ::score::crypto::Expected<std::size_t, ::score::crypto::daemon::common::DaemonErrorCode> FinalizeSign(
        score::cpp::span<std::uint8_t> signature) override;

    /// @brief Signs in one call through EVP_DigestSign, OpenSSL's one-shot entry
    ///        point.
    [[nodiscard]] ::score::crypto::Expected<std::size_t, ::score::crypto::daemon::common::DaemonErrorCode>
    SingleShotSign(score::cpp::span<const std::uint8_t> data, score::cpp::span<std::uint8_t> signature) override;

    /// @brief Check if the given algorithm is supported by this handler.
    [[nodiscard]] static bool IsAlgorithmSupported(const common::AlgorithmId& algorithm) noexcept;

  private:
    /// @brief The caller's signature buffer together with the curve it must hold.
    struct SignatureTarget
    {
        score::cpp::span<std::uint8_t> buffer;  ///< At least 2 * field_size bytes.
        std::size_t field_size;                 ///< Byte length of r and of s.
    };

    /// @brief Resolves and length-checks the caller's signature output buffer.
    ///
    /// Returns the curve's field size alongside the buffer so that the caller
    /// does not repeat the algorithm lookup this function already validated.
    [[nodiscard]] ::score::crypto::Expected<SignatureTarget, ::score::crypto::daemon::common::DaemonErrorCode>
    ResolveSignatureBuffer(score::cpp::span<std::uint8_t> signature) const;

    ecdsa::Stream m_stream;

    static constexpr std::string_view LOG_PREFIX = "[OPENSSL_ECDSA_SIGN_HANDLER]";
};

}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_SIGN_OPENSSL_ECDSA_SIGN_HANDLER_HPP

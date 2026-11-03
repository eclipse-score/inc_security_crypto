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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_DETAIL_SIGNATURE_COMMON_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_DETAIL_SIGNATURE_COMMON_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/context_mode.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/handler/i_handler.hpp"

#include <openssl/evp.h>

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace score::crypto::daemon::provider::score_provider::openssl::handler::signature
{

/// @brief Owns the digest context and bound key of one signature context (ECDSA, RSA-PSS or Ed25519).
///
/// Signing and verification differ only in which EVP_Digest* family they call,
/// so the setup and teardown either direction needs live here and each handler
/// supplies its own three OpenSSL calls.
class Stream final
{
  public:
    Stream() = default;
    ~Stream();

    Stream(const Stream&) = delete;
    Stream& operator=(const Stream&) = delete;
    Stream(Stream&&) = delete;
    Stream& operator=(Stream&&) = delete;

    /// @brief Validates the bound key against @p algorithm and allocates a digest context.
    ///
    /// @note The algorithm itself is assumed already validated by the caller's
    ///       own IsAlgorithmSupported() (checked at handler construction time);
    ///       this only checks that the bound key matches it.
    ///
    /// @param init_params Context initialization parameters; retained so that
    ///        Reset() can rebuild the context from them.
    [[nodiscard]] Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode> Bind(
        const ::score::crypto::daemon::provider::handler::InitializationParams& init_params,
        const common::AlgorithmId& algorithm);

    /// @brief Replaces the digest context with a fresh one.
    ///
    /// @pre Bind() has succeeded.
    /// @note EVP_Digest{Sign,Verify}Init cannot restart a context that already
    ///       carries accumulated data, so a stream that begins again needs a new
    ///       EVP_MD_CTX rather than a reinitialised one.
    [[nodiscard]] Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode> Restart();

    /// @brief The digest context, or nullptr before Bind().
    [[nodiscard]] EVP_MD_CTX* Context() const noexcept
    {
        return m_md_ctx;
    }

    /// @brief The bound key pair, or nullptr when none is bound.
    [[nodiscard]] EVP_PKEY* Key() const noexcept;

    /// @brief The parameters Bind() was given, for rebuilding on Reset().
    [[nodiscard]] const ::score::crypto::daemon::provider::handler::InitializationParams& InitParams() const noexcept
    {
        return m_init_params;
    }

  private:
    void Free() noexcept;

    EVP_MD_CTX* m_md_ctx{nullptr};
    ::score::crypto::daemon::provider::handler::InitializationParams m_init_params;
};

/// @brief Convert a DER ECDSA-Sig-Value into fixed-length r‖s.
/// @param field_size Byte length of r and of s.
[[nodiscard]] Expected<common::OwnedBuffer, ::score::crypto::daemon::common::DaemonErrorCode>
DerToP1363(const std::uint8_t* der, std::size_t der_len, std::size_t field_size);

/// @brief Convert fixed-length r‖s into a DER ECDSA-Sig-Value.
[[nodiscard]] Expected<common::OwnedBuffer, ::score::crypto::daemon::common::DaemonErrorCode>
P1363ToDer(const std::uint8_t* raw, std::size_t raw_len, std::size_t field_size);

/// @brief Configure RSA-PSS padding, salt length and MGF1 digest on a raw EVP_PKEY_CTX.
/// @param pkey_context The initialized sign/verify EVP_PKEY_CTX to configure.
/// @param digest The digest used for the MGF1 mask generation function.
/// @param salt_length RSA_PSS_SALTLEN_DIGEST, RSA_PSS_SALTLEN_AUTO or an explicit salt length in bytes.
/// @return false if the context, digest, or any RSA-PSS parameter could not be set.
[[nodiscard]] bool ConfigureRsaPssPkeyContext(EVP_PKEY_CTX* pkey_context,
                                              const EVP_MD* digest,
                                              int salt_length) noexcept;

/// @brief Configure an initialized OpenSSL digest-sign/verify context for RSA-PSS.
/// @param context The initialized digest-sign/verify context to configure.
/// @param algorithm The RSA-PSS signature algorithm identifier, used to look up the digest.
/// @param salt_length RSA_PSS_SALTLEN_DIGEST for signing (fixed per RFC 8017 §9.1); RSA_PSS_SALTLEN_AUTO
///        for verification, so signatures using any legal salt length are accepted.
/// @return an initialization error if the context or any RSA-PSS parameter could not be configured.
[[nodiscard]] Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode>
ConfigureRsaPssContext(EVP_MD_CTX* context, std::string_view algorithm, int salt_length) noexcept;

}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler::signature

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_DETAIL_SIGNATURE_COMMON_HPP

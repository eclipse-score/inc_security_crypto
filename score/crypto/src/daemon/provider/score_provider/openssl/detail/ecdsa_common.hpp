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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_DETAIL_ECDSA_COMMON_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_DETAIL_ECDSA_COMMON_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/handler/i_handler.hpp"

#include <openssl/evp.h>

#include <cstddef>
#include <cstdint>

namespace score::crypto::daemon::provider::score_provider::openssl::handler::ecdsa
{

/// @brief Whether @p algorithm names a complete ECDSA signature scheme.
///
/// A signature algorithm must name the digest as well as the curve: there is no
/// implied default pairing. Requiring it here means the bare key form
/// ("ECDSA-P256") is rejected at CTX_CREATE rather than surviving until the
/// first Init(), where the failure would be much harder to attribute.
[[nodiscard]] bool IsAlgorithmSupported(const common::AlgorithmId& algorithm) noexcept;

/// @brief Owns the digest context and bound key of one ECDSA context.
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

    /// @brief Validates the bound key and allocates a digest context.
    ///
    /// @param init_params Context initialization parameters; retained so that
    ///        Reset() can rebuild the context from them.
    /// @param algorithm The context's algorithm, checked against
    ///        IsAlgorithmSupported().
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

}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler::ecdsa

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_DETAIL_ECDSA_COMMON_HPP

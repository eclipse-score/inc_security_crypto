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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_KEY_MANAGEMENT_OPENSSL_KEY_HANDLER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_KEY_MANAGEMENT_OPENSSL_KEY_HANDLER_HPP

#include "score/crypto/src/daemon/key_management/interfaces/i_key_handler.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

// Forward declaration of OpenSSL's EVP_PKEY so that this header — which is part
// of a target without an OpenSSL dependency — stays free of <openssl/*.h>.
// EVP_PKEY is `typedef struct evp_pkey_st EVP_PKEY`, so a pointer to the
// incomplete type is layout-compatible with the real one.
struct evp_pkey_st;

namespace score::crypto::daemon::provider::openssl
{

/// Calls EVP_PKEY_free() on the managed key.
///
/// Defined out-of-line so that this header stays free of <openssl/*.h>; that is
/// also why EvpPkeyPtr manages an incomplete type, which is well-formed as long
/// as the deleter is not instantiated here.
struct EvpPkeyDeleter
{
    void operator()(evp_pkey_st* pkey) const noexcept;
};

/// Owning handle to an OpenSSL EVP_PKEY.
using EvpPkeyPtr = std::unique_ptr<evp_pkey_st, EvpPkeyDeleter>;

/// Owns the key material of a single OpenSSL key.
///
/// Two shapes are supported, distinguished by ProviderKeyHandle::is_asymmetric:
///
///   - **Symmetric** (AES, HMAC): a heap-allocated byte buffer. Crypto operation
///     handlers (MAC, cipher) downcast the IKeyHandler to this type and call
///     GetRawKeyBytes() for direct access.
///   - **Asymmetric** (ECDSA): an owned EVP_PKEY holding the key pair. Sign and
///     verify handlers call GetPkey(); the same object serves both, because an
///     EVP_PKEY produced by key generation carries the private and public half.
///
/// Destruction calls Release() as a safety net; Release() is idempotent and
/// zeroizes / frees whichever representation is in use.
class OpenSslKeyHandler final : public key_management::IKeyHandler
{
  public:
    /// Constructs a symmetric key handler taking ownership of @p key_bytes.
    OpenSslKeyHandler(std::vector<std::uint8_t> key_bytes, const key_management::ProviderKeyHandle& handle) noexcept;

    /// Constructs an asymmetric key handler taking ownership of @p pkey.
    ///
    /// Taking an EvpPkeyPtr rather than a raw pointer makes the ownership
    /// transfer explicit at the call site and keeps the caller's error paths
    /// leak-free.
    OpenSslKeyHandler(EvpPkeyPtr pkey, const key_management::ProviderKeyHandle& handle) noexcept;

    ~OpenSslKeyHandler() override;

    OpenSslKeyHandler(const OpenSslKeyHandler&) = delete;
    OpenSslKeyHandler& operator=(const OpenSslKeyHandler&) = delete;
    OpenSslKeyHandler(OpenSslKeyHandler&&) = delete;
    OpenSslKeyHandler& operator=(OpenSslKeyHandler&&) = delete;

    [[nodiscard]] const key_management::ProviderKeyHandle& GetHandle() const noexcept override;

    [[nodiscard]] ::score::crypto::Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode> Release()
        override;

    [[nodiscard]] ::score::crypto::Expected<key_management::SecureKeyBytes,
                                            ::score::crypto::daemon::common::DaemonErrorCode>
    Export() const override;

    [[nodiscard]] common::ProviderId GetProviderId() const noexcept override;

    /// Direct access to managed symmetric key material without opaque_id round-trip.
    /// Returns nullptr for asymmetric keys or after Release().
    [[nodiscard]] const std::uint8_t* GetRawKeyBytes(std::size_t& out_size) const noexcept;

    /// Direct access to the managed EVP_PKEY for asymmetric keys.
    /// Returns nullptr for symmetric keys or after Release(). Ownership stays here.
    [[nodiscard]] evp_pkey_st* GetPkey() const noexcept;

  private:
    std::vector<std::uint8_t> m_key_bytes;
    EvpPkeyPtr m_pkey;
    key_management::ProviderKeyHandle m_handle;
    bool m_released;
};

}  // namespace score::crypto::daemon::provider::openssl

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_KEY_MANAGEMENT_OPENSSL_KEY_HANDLER_HPP

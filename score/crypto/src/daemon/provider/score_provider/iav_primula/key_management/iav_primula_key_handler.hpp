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
/// @file iav_primula_key_handler.hpp
/// @brief Key handler for IAV-Primula provider keys.

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_IAV_PRIMULA_KEY_HANDLER_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_IAV_PRIMULA_KEY_HANDLER_HPP

#include "score/crypto/src/daemon/key_management/interfaces/i_key_handler.hpp"
#include "score/iav_primula/include/iav_primula_ffi.h"
#include <vector>

namespace score::crypto::daemon::provider::score_provider::iav_primula
{

/// @brief Key handler for IAV-Primula post-quantum keys.
///
/// Owns an optional native IAV-Primula key handle and a cached copy of the
/// public key. The native handle is destroyed and the cached key material is
/// cleared when Release() is called or the handler is destroyed.
///
/// Imported public keys do not have a native key handle.
class IavPrimulaKeyHandler final : public key_management::IKeyHandler
{
  public:
    /// @brief Create a key handler for an IAV-Primula key.
    ///
    /// The handler takes ownership of native_key and takes a copy of the
    /// provider key metadata. native_key may be nullptr for imported public
    /// keys.
    IavPrimulaKeyHandler(iav_primula_key_handle* native_key,
                         std::vector<std::uint8_t> public_key,
                         const key_management::ProviderKeyHandle& handle) noexcept;
    ~IavPrimulaKeyHandler() override;
    IavPrimulaKeyHandler(const IavPrimulaKeyHandler&) = delete;
    IavPrimulaKeyHandler& operator=(const IavPrimulaKeyHandler&) = delete;
    IavPrimulaKeyHandler(const IavPrimulaKeyHandler&&) = delete;
    IavPrimulaKeyHandler& operator=(const IavPrimulaKeyHandler&&) = delete;
    /// @brief Return the provider metadata associated with the key.
    ///
    /// The returned metadata contains the provider ID, algorithm, permissions,
    /// and key properties. It does not expose the native IAV-Primula key handle.
    [[nodiscard]] const key_management::ProviderKeyHandle& GetHandle() const noexcept override;
    /// @brief Release the native key handle and cached public key material.
    ///
    /// This operation is idempotent and can safely be called more than once.
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> Release() override;
    /// @brief Export the cached public key.
    ///
    /// Export requires the corresponding key permission and is not allowed
    /// after the key has been released.
    [[nodiscard]] Expected<key_management::SecureKeyBytes, common::DaemonErrorCode> Export() const override;
    /// @brief Return the numeric identifier of the owning provider instance.
    ///
    /// The identifier is stored in the provider key metadata and is used to
    /// associate the key with the provider that created or imported it.
    [[nodiscard]] common::ProviderId GetProviderId() const noexcept override;
    /// @brief Return the native IAV-Primula key handle.
    ///
    /// Returns nullptr when the key was imported as public key material or has
    /// already been released. The returned handle remains owned by this handler.
    [[nodiscard]] iav_primula_key_handle* GetNativeHandle() const noexcept
    {
        return m_native_key;
    }
    /// @brief Return a non-owning pointer to the cached public key.
    ///
    /// The pointer remains valid until the key is released or the handler is
    /// destroyed. Returns nullptr and sets size to zero after release.
    [[nodiscard]] const std::uint8_t* GetPublicKey(std::size_t& size) const noexcept;

  private:
    iav_primula_key_handle* m_native_key;        ///< Owned native key handle, or nullptr for public-only keys.
    std::vector<std::uint8_t> m_public_key;      ///< Cached public key material.
    key_management::ProviderKeyHandle m_handle;  ///< Provider metadata associated with the key.
    bool m_released{false};                      ///< Whether the key material has already been released.
};
}  // namespace score::crypto::daemon::provider::score_provider::iav_primula

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_IAV_PRIMULA_KEY_HANDLER_HPP

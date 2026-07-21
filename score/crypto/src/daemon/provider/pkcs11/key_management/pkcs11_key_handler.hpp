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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_KEY_MANAGEMENT_PKCS11_KEY_HANDLER_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_KEY_MANAGEMENT_PKCS11_KEY_HANDLER_HPP

#include "score/crypto/daemon/key_management/interfaces/i_key_handler.hpp"
#include "score/crypto/daemon/provider/pkcs11/key_management/pkcs11_key_store.hpp"

#include <pkcs11.h>

#include <atomic>
#include <cstdint>
#include <memory>
#include <utility>

namespace score::crypto::daemon::provider::pkcs11
{

/// IKeyHandler implementation for PKCS#11 keys.
///
/// Holds a weak reference to the Pkcs11KeyStore that owns the opaque-id
/// map. On Release(), calls store->Release() to destroy the PKCS#11 object
/// and erase the map entry. Export() returns kNotPermitted for all PKCS#11 keys.
class Pkcs11KeyHandler final : public key_management::IKeyHandler
{
  public:
    Pkcs11KeyHandler(std::weak_ptr<Pkcs11KeyStore> key_store, key_management::ProviderKeyHandle key_handle) noexcept;

    ~Pkcs11KeyHandler() override;

    Pkcs11KeyHandler(const Pkcs11KeyHandler&) = delete;
    Pkcs11KeyHandler& operator=(const Pkcs11KeyHandler&) = delete;
    Pkcs11KeyHandler(Pkcs11KeyHandler&&) = delete;
    Pkcs11KeyHandler& operator=(Pkcs11KeyHandler&&) = delete;

    [[nodiscard]] const key_management::ProviderKeyHandle& GetHandle() const noexcept override;

    [[nodiscard]] common::ProviderId GetProviderId() const noexcept override;

    [[nodiscard]] score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Release()
        override;

    [[nodiscard]] score::crypto::Expected<key_management::SecureKeyBytes,
                                          score::crypto::daemon::common::DaemonErrorCode>
    Export() const override;

    /// Direct access to PKCS#11 session key without opaque_id round-trip.
    [[nodiscard]] std::pair<CK_SESSION_HANDLE, CK_OBJECT_HANDLE> GetSessionKey() const noexcept;

    /// Resolve a usable PKCS#11 object handle for the given handler session.
    ///
    /// For session-object keys (GenerateKey / ImportKey) the stored handle is
    /// returned directly — it is valid on any session.
    ///
    /// For token-object keys (LoadKey) C_FindObjects is re-run on handler_session
    /// using the stored SearchTemplate, returning a fresh session-local handle.
    /// Multiple independent handlers may call this concurrently on the same key.
    ///
    /// Returns CK_INVALID_HANDLE on any error (key not found, module gone, etc.).
    /// Resolve a PKCS#11 key for use on a crypto operation.
    ///
    /// For session-object keys: returns the creating session + stored handle
    /// and acquires the per-key mutex exclusively.  The caller must hold the
    /// returned ResolvedKey for the full duration of the crypto operation
    /// (C_SignInit through C_SignFinal) to serialize concurrent access.
    ///
    /// For token-object keys: re-runs C_FindObjects on handler_session,
    /// returning a session-local handle with no lock.
    ///
    /// Returns an invalid ResolvedKey on any error.
    [[nodiscard]] Pkcs11KeyStore::ResolvedKey ResolveObject(CK_SESSION_HANDLE handler_session) const noexcept;

  private:
    std::weak_ptr<Pkcs11KeyStore> m_key_store;
    key_management::ProviderKeyHandle m_key_handle;
    std::atomic<bool> m_released;
};

}  // namespace score::crypto::daemon::provider::pkcs11

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_KEY_MANAGEMENT_PKCS11_KEY_HANDLER_HPP

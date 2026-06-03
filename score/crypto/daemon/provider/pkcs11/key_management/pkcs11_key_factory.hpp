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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_KEY_MANAGEMENT_PKCS11_KEY_FACTORY_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_KEY_MANAGEMENT_PKCS11_KEY_FACTORY_HPP

#include "score/crypto/daemon/common/daemon_error.hpp"
#include "score/crypto/daemon/key_management/interfaces/i_key_factory.hpp"

#include <memory>

namespace score::crypto::daemon::provider::pkcs11
{

class Pkcs11Provider;
class Pkcs11Module;
class Pkcs11KeyStore;

/// IKeyFactory implementation for PKCS#11 key generation and import.
///
/// Pkcs11KeyFactory generates and imports PKCS#11 session keys (CKA_TOKEN=false).
/// It injects a weak_ptr<Pkcs11Provider> for HSM access and a shared_ptr<Pkcs11KeyStore>
/// for opaque-id allocation and session-key storage.
///
/// Generated/imported keys are wrapped in Pkcs11KeyHandler instances that hold
/// weak_ptr<Pkcs11KeyStore> for Release callbacks.
class Pkcs11KeyFactory : public key_management::IKeyFactory
{
  public:
    /// Constructor.
    ///
    /// \param provider  weak_ptr to the parent Pkcs11Provider (for AcquireSession, session management)
    /// \param module    weak_ptr to the Pkcs11Module (for GetFunctionList access)
    /// \param key_store shared_ptr to the Pkcs11KeyStore (for opaque_id allocation and lookup)
    Pkcs11KeyFactory(std::weak_ptr<Pkcs11Provider> provider,
                     std::weak_ptr<Pkcs11Module> module,
                     std::shared_ptr<Pkcs11KeyStore> key_store);

    ~Pkcs11KeyFactory() override = default;

    Pkcs11KeyFactory(const Pkcs11KeyFactory&) = delete;
    Pkcs11KeyFactory& operator=(const Pkcs11KeyFactory&) = delete;
    Pkcs11KeyFactory(Pkcs11KeyFactory&&) = delete;
    Pkcs11KeyFactory& operator=(Pkcs11KeyFactory&&) = delete;

    /// Generate a PKCS#11 session key via C_GenerateKey.
    ///
    /// Acquires a session from the provider, generates the key, and registers it in the store.
    [[nodiscard]] score::crypto::Expected<key_management::IKeyHandler::Sptr,
                                          score::crypto::daemon::common::DaemonErrorCode>
    GenerateKey(const key_management::KeyGenerationRequest& request) override;

    /// Import raw key material via C_CreateObject (session object, CKA_TOKEN=false).
    ///
    /// Acquires a session from the provider, creates an object, and registers it in the store.
    [[nodiscard]] score::crypto::Expected<key_management::IKeyHandler::Sptr,
                                          score::crypto::daemon::common::DaemonErrorCode>
    ImportKey(const key_management::KeyImportRequest& request) override;

  private:
    std::weak_ptr<Pkcs11Provider> m_provider;
    std::weak_ptr<Pkcs11Module> m_module;
    std::shared_ptr<Pkcs11KeyStore> m_key_store;
};

}  // namespace score::crypto::daemon::provider::pkcs11

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_KEY_MANAGEMENT_PKCS11_KEY_FACTORY_HPP

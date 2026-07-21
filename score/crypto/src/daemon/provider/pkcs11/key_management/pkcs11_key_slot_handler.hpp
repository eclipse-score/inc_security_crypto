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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_KEY_MANAGEMENT_PKCS11_KEY_SLOT_HANDLER_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_KEY_MANAGEMENT_PKCS11_KEY_SLOT_HANDLER_HPP

#include "score/crypto/daemon/key_management/interfaces/i_key_slot_handler.hpp"
#include "score/crypto/daemon/key_management/interfaces/key_slot_config.hpp"

#include <memory>
#include <string_view>

namespace score::crypto::daemon::provider::pkcs11
{

// Forward declarations
class Pkcs11Provider;
class Pkcs11Module;
class Pkcs11KeyStore;

/// PKCS#11 implementation of IKeySlotHandler.
///
/// Manages key slots that reside as token objects on a PKCS#11 token.
/// Slot identification is driven by slot.provider_params:
///   - kPkcs11Label      → CKA_LABEL in C_FindObjects template
///   - kPkcs11ObjectId   → CKA_ID (hex string) in C_FindObjects template
///   - kPkcs11ObjectClass → CKA_CLASS (default: CKO_SECRET_KEY)
///
/// LoadKey verifies the token object exists, stores its search template in the
/// Pkcs11KeyStore, then releases the discovery session. Crypto handlers call
/// Pkcs11KeyHandler::ResolveObject() with their own session to obtain a
/// handle at bind time. The returned IKeyHandler delegates release to the store.
class Pkcs11KeySlotHandler final : public key_management::IKeySlotHandler
{
  public:
    Pkcs11KeySlotHandler(std::shared_ptr<Pkcs11Provider> provider,
                         std::weak_ptr<Pkcs11Module> module,
                         std::shared_ptr<Pkcs11KeyStore> key_store);

    ~Pkcs11KeySlotHandler() override = default;

    Pkcs11KeySlotHandler(const Pkcs11KeySlotHandler&) = delete;
    Pkcs11KeySlotHandler& operator=(const Pkcs11KeySlotHandler&) = delete;
    Pkcs11KeySlotHandler(Pkcs11KeySlotHandler&&) = delete;
    Pkcs11KeySlotHandler& operator=(Pkcs11KeySlotHandler&&) = delete;

    /// Find the token object matching slot.provider_params and return a key handler.
    ///
    /// Uses C_FindObjectsInit / C_FindObjects / C_FindObjectsFinal.
    [[nodiscard]] score::crypto::Expected<key_management::IKeyHandler::Sptr,
                                          score::crypto::daemon::common::DaemonErrorCode>
    LoadKey(const key_management::KeySlotConfig& slot) override;

    /// Return kOccupied if the token object exists, kEmpty otherwise.
    [[nodiscard]] score::crypto::Expected<score::mw::crypto::KeySlotState,
                                          score::crypto::daemon::common::DaemonErrorCode>
    GetSlotState(const key_management::KeySlotConfig& slot) override;

    /// Return slot metadata from config and token object attributes.
    [[nodiscard]] score::crypto::Expected<score::mw::crypto::KeySlotInfo,
                                          score::crypto::daemon::common::DaemonErrorCode>
    GetSlotInfo(const key_management::KeySlotConfig& slot) override;

  private:
    std::shared_ptr<Pkcs11Provider> m_provider;
    std::weak_ptr<Pkcs11Module> m_module;
    std::shared_ptr<Pkcs11KeyStore> m_key_store;

    static constexpr std::string_view LOG_PREFIX = "[PKCS11_KEY_SLOT_HANDLER]";
};

}  // namespace score::crypto::daemon::provider::pkcs11

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_KEY_MANAGEMENT_PKCS11_KEY_SLOT_HANDLER_HPP

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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_INTERFACES_I_CERT_SLOT_CATALOG_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_INTERFACES_I_CERT_SLOT_CATALOG_HPP

namespace score::crypto::daemon::cert_management
{

class CertSlotRegistry;

/// Abstract source of certificate slot definitions.
///
/// A catalog is a **one-shot loader**: it is instantiated, Load() is called
/// exactly once to populate the registry, and the catalog object may then be
/// discarded. This keeps CertSlotRegistry a pure registry with no knowledge
/// of where slot definitions come from.
///
/// Current implementations:
///   - ConfigDrivenSlotCatalog — reads slot definitions from parsed CertificateConfig
///
/// Future implementations:
///   - SecureStoreCatalog — reads provisioned slot metadata from a TEE-backed store
///   - Pkcs11CertSlotCatalog — enumerates PKCS#11 token certificate objects
///
/// @note Catalog implementations MUST be idempotent: calling Load() on an
///       already-populated registry is safe. Duplicate slot names are rejected
///       by the registry boundary rather than overwriting existing slots.
class ICertSlotCatalog
{
  public:
    virtual ~ICertSlotCatalog() = default;

    /// Register all certificate slots from this catalog into the given registry.
    ///
    /// Each slot is registered via CertSlotRegistry::RegisterSlot(CertSlotConfig).
    /// The catalog does NOT retain a reference to the registry after this call.
    ///
    /// @param registry  The central CertSlotRegistry to populate.
    virtual void Load(CertSlotRegistry& registry) = 0;
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_INTERFACES_I_CERT_SLOT_CATALOG_HPP

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

#ifndef SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_I_KEY_SLOT_CATALOG_HPP
#define SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_I_KEY_SLOT_CATALOG_HPP

namespace score::crypto::daemon::key_management
{

class SlotRegistry;

/// @brief Abstract source of key slot definitions.
///
/// A catalog is a **one-shot loader**: it is instantiated, `Load()` is called
/// exactly once to populate the registry, and the catalog object may then be
/// discarded. This keeps SlotRegistry a pure registry with no knowledge
/// of where slot definitions come from.
///
/// Current implementations:
///   - `ConfigDrivenSlotCatalog`  — reads slot definitions from the parsed KeyConfig
///
/// Future implementations:
///   - `SecureStoreCatalog`   — reads provisioned slot metadata from a TEE-backed store
///   - `Pkcs11SlotCatalog`    — enumerates PKCS#11 token objects and registers them
///
/// @note Catalog implementations MUST be idempotent: calling `Load()` on an
///       already-populated registry is safe and duplicate slot names are
///       rejected by the registry boundary instead of overwriting existing slots.
class IKeySlotCatalog
{
  public:
    virtual ~IKeySlotCatalog() = default;

    /// @brief Register all slots from this catalog into the given registry.
    ///
    /// Each slot is registered via `SlotRegistry::RegisterSlot(KeySlotConfig)`.
    /// The catalog does NOT retain a reference to the registry after this call.
    ///
    /// @param registry  The central SlotRegistry to populate.
    virtual void Load(SlotRegistry& registry) = 0;
};

}  // namespace score::crypto::daemon::key_management

#endif  // SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_I_KEY_SLOT_CATALOG_HPP

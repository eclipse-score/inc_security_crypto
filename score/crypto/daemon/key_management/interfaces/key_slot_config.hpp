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

#ifndef SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_KEY_SLOT_CONFIG_HPP
#define SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_KEY_SLOT_CONFIG_HPP

#include "score/crypto/daemon/common/types.hpp"
#include "score/mw/crypto/api/common/types.hpp"

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace score::crypto::daemon::key_management
{

/// @brief Access control policy for a key slot.
struct AccessPolicy
{
    /// @brief UIDs permitted to read from this slot (LoadKey, GetKeySlotInfo, ResolveResource).
    std::vector<uint32_t> allowed_uids;

    /// @brief UIDs permitted to write to this slot (GenerateKey, persist/import).
    ///
    /// A UID not in this list can still load and use existing keys from the slot;
    /// it simply cannot create or replace key material.
    std::vector<uint32_t> allowed_write_uids;
};

/// @brief Well-known keys for SlotDeploymentInfo::metadata.
///
/// Metadata captures slot-level lifecycle state that the slot management
/// layer (SlotRegistry, catalogs) reads without involving a provider.
/// All values are UTF-8 strings; consumers must validate before use.
namespace metadata_keys
{
/// Slot availability override: "active" | "disabled" | "unavailable".
///
/// When absent the slot is assumed active.  The catalog or deployment
/// loader writes this key; the SlotRegistry reads it at load time.
inline constexpr std::string_view kAvailability = "availability";

/// ISO-8601 UTC timestamp of the last successful key provisioning.
/// Example: "2025-11-03T08:42:00Z"
inline constexpr std::string_view kProvisionedAt = "provisioned_at";

/// Monotonically increasing update counter (decimal string).
/// Incremented by the writer on every key replacement.
inline constexpr std::string_view kUpdateCounter = "update_counter";

/// Hash of the key material (hex-encoded digest).
/// Example: "sha256:a1b2c3d4e5f6..."
inline constexpr std::string_view kHash = "hash";

/// Slot name containing the Key Encryption Key (KEK) for encrypting/decrypting this key.
/// Example: "vehicle/master-key"
inline constexpr std::string_view kKekKeySlotName = "kek.keyslotname";

/// Algorithm used by the Key Encryption Key (KEK).
/// Example: "AES-256-GCM", "AES-256-CBC"
inline constexpr std::string_view kKekAlgorithm = "kek.algo";

/// Initialization Vector (IV) for the Key Encryption Key (KEK) operations (hex-encoded).
/// Example: "0102030405060708090a0b0c0d0e0f10"
inline constexpr std::string_view kKekIv = "kek.iv";
}  // namespace metadata_keys

/// @brief Well-known keys for SlotDeploymentInfo::key_properties.
///
/// Each IKeySlotHandler reads only the entries it understands, silently
/// ignoring others. Adding a new backend requires only a daemon config
/// change — no client API change and no application rebuild.
namespace deployment_keys
{
/// File path for file-backed SW providers (e.g., OpenSSL + FileBackedSlotHandler).
inline constexpr std::string_view kKeyPath = "key_path";
/// Encoding of the key data at kKeyPath: "raw", "pem", "der".
inline constexpr std::string_view kKeyFormat = "key_format";
/// Plain text key material (hex-encoded or base64-encoded).
/// **Warning**: Only use for testing/development. Avoid in production.
/// Example: "0102030405060708090a0b0c0d0e0f10"
inline constexpr std::string_view kKey = "key";
/// PKCS#11 CKA_LABEL — human-readable object label inside the token.
inline constexpr std::string_view kPkcs11Label = "pkcs11.label";
/// PKCS#11 CKA_ID — hex-encoded binary object ID (e.g., "0102abcd").
inline constexpr std::string_view kPkcs11ObjectId = "pkcs11.object_id";
/// PKCS#11 CKA_CLASS as string: "secret_key", "private_key", "public_key".
inline constexpr std::string_view kPkcs11ObjectClass = "pkcs11.object_class";
/// TEE / PSA persistent key identifier (decimal or hex string).
inline constexpr std::string_view kTeeKeyId = "tee.key_id";
/// PSA Crypto key identifier (uint32 expressed as decimal string).
inline constexpr std::string_view kPsaKeyId = "psa.key_id";
}  // namespace deployment_keys

/// @brief Dynamic information loaded from a slot's deployment descriptor.
///
/// The deployment path (file or folder) is read by the DeploymentLoader at
/// slot load time. The content is provider-agnostic at the struct level;
/// each IKeySlotHandler interprets the `key_properties` entries it understands.
///
/// For file-backed (OpenSSL) providers:
///   key_properties = {"key_path": "/path/to/key.bin", "key_format": "raw"}
///
/// For PKCS#11 / HSM providers:
///   key_properties = {"pkcs11.label": "my_hmac", "pkcs11.object_id": "0102ab"}
///
/// For TEE / PSA providers:
///   key_properties = {"tee.key_id": "42"}
struct SlotDeploymentInfo
{
    /// @brief Slot-level dynamic metadata (extensible string map).
    ///
    /// Well-known keys: metadata_keys::kAvailability, metadata_keys::kLabel,
    /// metadata_keys::kProvisionedAt, metadata_keys::kUpdateCounter.
    /// Providers and extensions may define additional entries.
    std::unordered_map<std::string, std::string> metadata;

    /// @brief Provider-specific key identification and location properties.
    ///
    /// Interpretation is provider-dependent: file-backed handlers read
    /// key_path/key_format; PKCS#11 handlers read pkcs11.label/object_id;
    /// TEE handlers read tee.key_id.
    std::unordered_map<std::string, std::string> key_properties;
};

/// @brief Immutable configuration for a key slot.
///
/// Owned centrally by the SlotRegistry. KeySlotDataNodes hold only a
/// SlotHandle referencing back to the central registry — they do NOT
/// copy this struct.
///
/// All fields are immutable after registration. Dynamic slot and key
/// information (availability, provider-specific identifiers, key material
/// location) is loaded from the deployment descriptor at `deployment_path`.
///
/// ### Provider Identity: Names vs. IDs
///
/// Configuration time: `provider_names` holds human-readable strings from config.
/// Runtime: `provider_ids` holds numeric IDs assigned by ProviderManager.
/// The conversion happens in SlotRegistry::ResolveProviderIds().
///
/// ### Multi-provider model
/// `provider_ids` is an ordered list of providers permitted to work with this
/// key slot. The first entry (`provider_ids[0]`) is the **primary provider** —
/// the only provider allowed to *modify* key material (generate, write, delete).
/// Subsequent entries are **secondary providers** that may *consume* the key for
/// crypto operations (MAC, cipher, sign, etc.) but cannot mutate it.
struct KeySlotConfig
{
    std::string slot_name;  ///< Human-readable resource ID (e.g., "vehicle/hmac-256")
    std::string algorithm;  ///< Algorithm string (e.g., "HMAC-SHA256", "AES-256-CMAC")

    /// @brief Config-time: Ordered provider names from config. [0] is the primary.
    std::vector<common::ProviderName> provider_names;

    /// @brief Runtime: Ordered numeric provider IDs. [0] is the primary (sole writer).
    ///        Populated by SlotRegistry::ResolveProviderIds() after ProviderManager
    ///        initialization. Subsequent entries are read-only consumers.
    std::vector<common::ProviderId> provider_ids;

    /// @brief Permitted crypto operations for keys loaded from this slot.
    score::mw::crypto::KeyOperationPermission allowed_operations{score::mw::crypto::KeyOperationPermission::kNone};

    /// @brief UID-based access control for this slot.
    AccessPolicy access_policy;

    /// @brief Path to the deployment descriptor (file or folder).
    ///
    /// The deployment descriptor holds dynamic slot metadata and provider-specific
    /// key identification/location data. Read by DeploymentLoader at slot load time.
    /// Must be an absolute path with no ".." traversal components.
    std::string deployment_path;

    /// @brief Format of the deployment descriptor: "kv" (default), "json", "bin".
    std::string deployment_format{"kv"};

    // -------------------------------------------------------------------
    // Convenience accessors
    // -------------------------------------------------------------------

    /// @brief Return the primary provider ID (numeric, sole writer).
    common::ProviderId GetPrimaryProviderId() const noexcept
    {
        return provider_ids.empty() ? common::kInvalidProviderId : provider_ids.front();
    }

    /// @brief True when numeric provider `id` is listed in provider_ids (primary or secondary).
    bool IsProviderAllowed(common::ProviderId id) const noexcept
    {
        for (const auto& p : provider_ids)
        {
            if (p == id)
            {
                return true;
            }
        }
        return false;
    }

    /// @brief True when the KeySlotConfig is structurally valid (at least one provider).
    bool IsValid() const noexcept
    {
        return !slot_name.empty() && !provider_ids.empty();
    }
};

}  // namespace score::crypto::daemon::key_management

#endif  // SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_KEY_SLOT_CONFIG_HPP

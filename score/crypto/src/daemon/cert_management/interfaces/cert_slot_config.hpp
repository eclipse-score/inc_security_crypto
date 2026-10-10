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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_INTERFACES_CERT_SLOT_CONFIG_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_INTERFACES_CERT_SLOT_CONFIG_HPP

#include "score/crypto/src/daemon/cert_management/interfaces/access_policy.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_types.hpp"

#include <cstdint>
#include <string>

namespace score::crypto::daemon::cert_management
{

// ---------------------------------------------------------------------------
// IntegrityPolicy
// ---------------------------------------------------------------------------

/// Integrity enforcement policy for a certificate slot.
///
/// kDisabled: no check is performed; descriptor hash fields are ignored even if present.
/// kRequired: LoadCertificate fails if the KV descriptor [certificate] section has no
///            cert_hash entry, or if the stored hash does not match the file content.
///            This prevents a compromised descriptor from bypassing the check.
///
/// The policy is a static slot property set at startup by the integrator. The actual
/// hash value and algorithm live in the KV descriptor [certificate] section and are
/// updated atomically by the writer whenever a certificate is stored.
enum class IntegrityPolicy : uint8_t
{
    kDisabled = 0,
    kRequired = 1,
};

// ---------------------------------------------------------------------------
// CertSlotConfig
// ---------------------------------------------------------------------------

/// Immutable configuration for a certificate slot.
///
/// Owned centrally by the CertSlotRegistry. CertSlotDataNodes hold only a
/// CertSlotHandle referencing back to the central registry — they do NOT
/// copy this struct.
///
/// All fields are immutable after registration. Dynamic certificate and CRL
/// content is stored in a deployment descriptor at deployment_path, using
/// the KV sections [metadata], [certificate], [certificate_metadata], [crl].
///
/// ### Storage backend
///
/// `storage_backend` is a scalar string that identifies which ICertSlotHandler
/// subclass manages the physical storage for this slot. It is immutable after
/// startup — a slot is structurally bound to one backend type. Changing the
/// backend requires reconfiguration and re-provisioning.
///
/// Built-in value: "DEFAULT" → FileBackedSlotHandler.
/// Any other value is treated as a provider name; the named provider must implement
/// ICertSlotHandler (e.g. Pkcs11CertSlotHandler for "pkcs11"). Backend-specific
/// parameters (file path, PKCS#11 token label, object handle) live in the KV
/// descriptor, not here.
///
/// Cert operations (parse, chain verify, CSR) are provider-agnostic and route to
/// the global software provider by default — they do not depend on this field.
///
/// ### Certificate format
///
/// The on-disk certificate format (PEM or DER) is NOT stored here; it is recorded
/// as cert_format in the [certificate] KV descriptor section and updated atomically
/// by the writer on each StoreCertificate call.
struct CertSlotConfig
{
    /// Human-readable resource ID for this slot (e.g., "device/tls-cert").
    ///
    /// Must be unique within the CertSlotRegistry. Used as the stable
    /// identifier in trust-store membership entries and API resource paths.
    std::string slot_name;

    /// Storage backend identifier. "DEFAULT" selects FileBackedSlotHandler;
    /// any other value is resolved as a provider name by CertManagementModule.
    /// The value is matched exactly (case-sensitive).
    std::string storage_backend{"DEFAULT"};

    /// UID-based access control for this slot.
    AccessPolicy access_policy;

    /// Path to the deployment descriptor (file or folder) for this cert slot.
    ///
    /// The deployment descriptor uses the KV format with sections defined in
    /// cert_section_names: [metadata], [certificate], [certificate_metadata], [crl].
    /// Must be an absolute path with no ".." traversal components.
    std::string deployment_path;

    /// Format of the deployment descriptor: "kv" (default), "json", "bin".
    std::string deployment_format{"kv"};

    /// Integrity enforcement policy. See IntegrityPolicy enum doc.
    IntegrityPolicy integrity_policy{IntegrityPolicy::kDisabled};

    // -----------------------------------------------------------------------
    // Convenience accessor
    // -----------------------------------------------------------------------

    /// True when the CertSlotConfig is structurally valid (non-empty name and backend).
    [[nodiscard]] bool IsValid() const noexcept
    {
        return !slot_name.empty() && !storage_backend.empty();
    }
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_INTERFACES_CERT_SLOT_CONFIG_HPP

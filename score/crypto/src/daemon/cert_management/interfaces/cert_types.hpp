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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_INTERFACES_CERT_TYPES_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_INTERFACES_CERT_TYPES_HPP

#include "score/crypto/src/api/common/types.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/types.hpp"

#include <climits>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace score::crypto::daemon::cert_management
{

// ---------------------------------------------------------------------------
// Opaque registry and trust-store identifiers
// ---------------------------------------------------------------------------

/// Monotonically increasing identifier for a certificate entry in the CertRegistry.
using CertRegistryId = uint64_t;

/// Compact identifier for a named trust store.
using TrustStoreId = uint32_t;

// ---------------------------------------------------------------------------
// Slot and store handles — thin wrappers around uint32_t indices
// ---------------------------------------------------------------------------

/// Runtime reference to a certificate slot held by the SlotRegistry.
///
/// The index maps to an entry in the SlotRegistry internal table.
/// Callers must not interpret or persist the raw index value across daemon
/// restarts; always resolve through CertManagementService.
struct CertSlotHandle
{
    uint32_t index{UINT32_MAX};

    [[nodiscard]] bool IsValid() const noexcept
    {
        return index != UINT32_MAX;
    }

    bool operator==(const CertSlotHandle& o) const noexcept
    {
        return index == o.index;
    }

    bool operator!=(const CertSlotHandle& o) const noexcept
    {
        return !(*this == o);
    }
};

/// Runtime reference to a named trust store held by TrustStoreManager.
struct TrustStoreHandle
{
    uint32_t index{UINT32_MAX};

    [[nodiscard]] bool IsValid() const noexcept
    {
        return index != UINT32_MAX;
    }

    bool operator==(const TrustStoreHandle& o) const noexcept
    {
        return index == o.index;
    }

    bool operator!=(const TrustStoreHandle& o) const noexcept
    {
        return !(*this == o);
    }
};

// ---------------------------------------------------------------------------
// Certificate chain metadata (precomputed at parse time)
// ---------------------------------------------------------------------------

/// Extracted X.509 fields used for chain building and trust store indexing.
///
/// Populated by a provider parser and cached in the CertObject.
/// All binary fields (skid, akid, fingerprint) are stored as raw bytes.
/// String fields use the RFC 4514 canonical representation.
struct CertChainMetadata
{
    /// RFC 4514 string representation of the Subject DN (e.g., "CN=...,O=...,C=...").
    std::string subject_canonical;

    /// RFC 4514 string representation of the Issuer DN.
    std::string issuer_canonical;

    /// DER-encoded Subject Key Identifier extension value; empty if the extension
    /// is absent from the certificate.
    std::vector<uint8_t> skid;

    /// DER-encoded Authority Key Identifier extension value; empty if absent.
    std::vector<uint8_t> akid;

    /// SHA-256 digest of the certificate's DER encoding (32 bytes).
    std::vector<uint8_t> fingerprint;

    /// Unix epoch seconds of the notBefore validity field.
    int64_t not_before_epoch_s{0};

    /// Unix epoch seconds of the notAfter validity field.
    int64_t not_after_epoch_s{0};

    /// True when the BasicConstraints extension marks this as a CA certificate.
    bool is_ca{false};
};

// ---------------------------------------------------------------------------
// Deployment descriptor section and key name constants
// ---------------------------------------------------------------------------

/// KV descriptor section names used for certificate and CRL storage.
///
/// The deployment descriptor maps section -> (key -> value) and follows the
/// same INI-style KV format used by key_management. These constants are the
/// canonical section names shared between FileBackedSlotHandler, the
/// deployment loader, and the DataNode serialization layer.
namespace cert_section_names
{

/// Slot-level lifecycle metadata (availability, provisioned_at, update_counter).
inline constexpr std::string_view kMetadata = "metadata";

/// Certificate file location and format for a cert slot.
inline constexpr std::string_view kCertificate = "certificate";

/// Cached parsed certificate metadata (subject, issuer, validity, extensions).
/// Written by the daemon on certificate save; read by catalogs at reload.
inline constexpr std::string_view kCertificateMetadata = "certificate_metadata";

/// CRL file location, format, and nextUpdate for the co-located CRL.
/// Section is absent when no CRL has been stored for the slot.
inline constexpr std::string_view kCrl = "crl";

/// Runtime enable/accept state for trust store members.
/// Written by TrustStoreManager on every mutation; absent until the first mutation.
inline constexpr std::string_view kTrustStoreState = "trust_store_state";

}  // namespace cert_section_names

/// KV descriptor key names within the cert_section_names sections.
namespace cert_deployment_keys
{

// ---- [certificate] section -----------------------------------------------

/// PKCS#11 token object label used by a token-backed certificate slot.
inline constexpr std::string_view kPkcs11Label = "pkcs11.label";

/// Hex-encoded PKCS#11 CKA_ID used by a token-backed certificate slot.
inline constexpr std::string_view kPkcs11ObjectId = "pkcs11.object_id";

/// Absolute path to the PEM or DER certificate file.
inline constexpr std::string_view kCertPath = "cert_path";

/// Encoding of the certificate file: "pem" or "der".
inline constexpr std::string_view kCertFormat = "cert_format";

// ---- [crl] section -------------------------------------------------------

/// Absolute path to the PEM or DER CRL file co-located with the cert slot.
inline constexpr std::string_view kCrlPath = "crl_path";

/// Encoding of the CRL file: "pem" or "der".
inline constexpr std::string_view kCrlFormat = "crl_format";

/// ISO-8601 UTC timestamp of the CRL's nextUpdate field.
/// Written when the CRL is imported; read by the daemon to schedule refresh.
inline constexpr std::string_view kCrlNextUpdate = "crl_next_update";

// ---- [certificate_metadata] section --------------------------------------

/// RFC 4514 canonical Subject DN string.
inline constexpr std::string_view kSubject = "subject";

/// RFC 4514 canonical Issuer DN string.
inline constexpr std::string_view kIssuer = "issuer";

/// ISO-8601 UTC timestamp corresponding to the notBefore validity field.
inline constexpr std::string_view kNotBefore = "not_before";

/// ISO-8601 UTC timestamp corresponding to the notAfter validity field.
inline constexpr std::string_view kNotAfter = "not_after";

/// Hex-encoded Subject Key Identifier extension value; empty string if absent.
inline constexpr std::string_view kSkid = "skid";

/// Hex-encoded Authority Key Identifier extension value; empty string if absent.
inline constexpr std::string_view kAkid = "akid";

/// "true" when the certificate is a CA (BasicConstraints cA=TRUE); "false" otherwise.
inline constexpr std::string_view kIsCA = "is_ca";

/// Hex-encoded SHA-256 fingerprint of the certificate DER encoding.
inline constexpr std::string_view kFingerprint = "fingerprint";

// ---- [metadata] section --------------------------------------------------

/// Slot availability override: "active" | "disabled" | "unavailable".
/// When absent, the slot is assumed active.
inline constexpr std::string_view kAvailability = "availability";

/// ISO-8601 UTC timestamp of the last successful certificate provisioning.
inline constexpr std::string_view kProvisionedAt = "provisioned_at";

/// Monotonically increasing update counter (decimal string).
/// Incremented on every certificate replacement.
inline constexpr std::string_view kUpdateCounter = "update_counter";

}  // namespace cert_deployment_keys

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_INTERFACES_CERT_TYPES_HPP

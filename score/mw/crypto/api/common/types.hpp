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

#ifndef SCORE_MW_CRYPTO_API_COMMON_TYPES_HPP
#define SCORE_MW_CRYPTO_API_COMMON_TYPES_HPP

#include "score/mw/crypto/api/common/error_domain.hpp"
#include "score/mw/crypto/api/common/fixed_capacity_string.hpp"

#include <array>
#include <cstdint>
#include <functional>
#include <optional>

namespace score
{
namespace mw
{
namespace crypto
{

/// @brief Application-defined name for config files (e.g., "KeySlot_42").
/// Only used at resolution time via ICryptoContext::ResolveResource().
///
/// Uses FixedCapacityString<64> — stack-allocated, no heap allocation.
/// Resource names are deployment-time configuration values (bounded, immutable).
/// All observed resource name strings are well under 64 characters.
using ResourceId = FixedCapacityString<64>;

/// @brief String-based algorithm identifier for extensibility (including PQC).
///
/// Uses FixedCapacityString<64> — a stack-allocated, non-heap-allocating string
/// that satisfies automotive safety requirements (deterministic memory, no heap
/// fragmentation) while preserving extensibility. New algorithms can be added
/// at the daemon level without modifying the client library — any algorithm name
/// up to 64 characters is accepted at runtime.
///
/// Examples: "AES-256-CBC", "SHA-256", "ECDSA-P256", "ML-KEM-768", "ML-DSA-65",
/// "SLH-DSA-SHA2-128s", "XMSS-SHA2_10_256"
///
/// Implicit conversion to std::string_view enables zero-copy interop.
/// Explicit conversion to std::string available for IPC serialization.
using AlgorithmId = FixedCapacityString<64>;

/// @brief Type of crypto resource managed by the daemon.
///
/// kKey and kCertificate identify live objects (key material, parsed certs);
/// kKeySlot and kCertSlot identify only persistent storage locations.
enum class ResourceType : uint8_t
{
    kProvider,                ///< Crypto provider / device
    kKeySlot,                 ///< Persistent key storage slot
    kCertSlot,                ///< Persistent certificate storage slot
    kVerificationTrustStore,  ///< Named group of trusted CA certificates used for certificate chain
                              ///< verification.
    kKey,                     ///< Key material (generated / loaded / derived / imported)
    kCertificate,             ///< Parsed or stored certificate object
    kCrl,                     ///< Certificate Revocation List — shares the same numeric id
                              ///< as the issuer certificate resource (differentiated by type field)
    kSecureObject,            ///< Secure storage entry
    kDataObject               ///< Generic data blob
};

/// @brief Persistence classification of a crypto resource.
enum class ResourcePersistence : uint8_t
{
    kPersistent,  ///< Survives context/stack destruction, stored in provider
    kEphemeral    ///< Auto-cleaned on context/stack destruction
};

/// @brief The sole runtime handle for all resolved crypto resources.
///
/// Applications resolve string-based ResourceId to CryptoResourceId once via
/// ICryptoContext::ResolveResource(), then use this compact struct for all
/// subsequent operations. No string fields — all comparisons are numeric/enum.
///
/// @note Struct is ~16 bytes with padding, fully numeric, cheap to copy and hash.
struct CryptoResourceId
{
    uint64_t id{0U};                                                   ///< Daemon-assigned, unique per session
    ResourceType type{ResourceType::kKeySlot};                         ///< Resource classification
    ResourcePersistence persistence{ResourcePersistence::kEphemeral};  ///< Lifetime
    uint16_t primary_provider{0U};                                     ///< Daemon-assigned numeric provider index.
                                                                       ///< Embeds device binding: identifies which
                                                                       ///< provider/device owns this resource.
                                                                       ///< 0 = unbound (e.g., trust anchors).

    constexpr bool operator==(const CryptoResourceId& other) const noexcept
    {
        return (id == other.id) && (type == other.type) && (persistence == other.persistence) &&
               (primary_provider == other.primary_provider);
    }

    constexpr bool operator!=(const CryptoResourceId& other) const noexcept
    {
        return !(*this == other);
    }
};

/// @brief Preference for selecting a crypto provider when not explicitly specified.
enum class ProviderType : uint8_t
{
    kDefault,            ///< Daemon selects the most appropriate provider
    kHardware,           ///< Require a hardware provider (HSM/TEE)
    kSoftware,           ///< Require a software provider (OpenSSL/wolfSSL)
    kHardwarePreferred,  ///< Prefer hardware, fall back to software
    kSoftwarePreferred   ///< Prefer software, fall back to hardware
};

/// @brief Certificate and key data encoding format.
enum class FormatType : uint8_t
{
    kDer,  ///< DER (binary) encoding
    kPem   ///< PEM (base64-armored) encoding
};

/// @brief State of a key slot.
///
/// Renamed from KeySlotStatus to disambiguate from CertificateStatus.
enum class KeySlotState : uint8_t
{
    kEmpty,     ///< Slot contains no key material
    kOccupied,  ///< Slot contains a key
    kLocked     ///< Slot is in use and cannot be modified
};

/// @brief Validity status of a certificate.
enum class CertificateStatus : uint8_t
{
    kValid,    ///< Certificate is valid
    kRevoked,  ///< Certificate has been revoked
    kExpired,  ///< Certificate has expired
    kUnknown   ///< Status cannot be determined
};

/// @brief Direction for symmetric cipher and AEAD operations.
enum class CipherDirection : uint8_t
{
    kEncrypt,  ///< Encryption / sealing direction
    kDecrypt   ///< Decryption / opening direction
};

/// @brief Intended usage mode for MAC and signature contexts.
///
/// Specifies whether the context will be used to generate (sign) or verify.
/// Used for:
///   - Key permission enforcement (kSign for generation, kVerify for verification).
///   - Provider-specific API selection (e.g. PKCS#11 C_SignInit vs C_VerifyInit).
///
/// @note CipherDirection covers encrypt/decrypt for symmetric ciphers.
///       OperationMode covers MAC generation/verification and future signature contexts.
enum class OperationMode : uint8_t
{
    kGenerate,  ///< MAC generation / signature creation
    kVerify     ///< MAC verification / signature verification
};

/// @brief Type of shared memory to allocate for the data plane.
enum class MemoryType : uint8_t
{
    kDefault,            ///< Daemon-managed shared memory, suitable for most providers.
                         ///< The daemon may copy data into provider-compatible memory internally.
    kProviderCompatible  ///< Memory directly usable by a specific provider (e.g., DMA-capable
                         ///< for HW/TEE), enabling true zero-copy from application through
                         ///< daemon to the crypto device.
};

/// @brief Controls the revocation checking strategy in ICertificateVerificationContext.
enum class RevocationCheckPolicy : uint8_t
{
    kNone,                ///< No revocation checking
    kCrlOnly,             ///< Check revocation using CRL only
    kOcspOnly,            ///< Check revocation using OCSP only
    kOcspWithCrlFallback  ///< Prefer OCSP, fall back to CRL if OCSP is unavailable
};

/// @brief Bitmask defining which cryptographic operations a key is permitted to perform.
///
/// Key operation permissions enforce the principle of least privilege: a key
/// configured for signing cannot be misused for encryption, and vice versa.
/// Permissions are assigned when a key slot is provisioned (daemon-side
/// configuration) and optionally constrained further at key generation time.
///
/// The permission model uses a capability-centric bitmask grouped by
/// operation category:
///   - **Data protection** (bits 0–3): encrypt, decrypt, wrap, unwrap
///   - **Authentication** (bits 4–7): sign, verify, mac, agree
///   - **Key lifecycle** (bits 8–10): derive, export, import
///
/// Composite presets are provided for common deployment patterns.
/// Use bitwise OR to combine individual permissions.
///
/// @note Permission enforcement is performed by the daemon at context
///       creation time. If a key's permissions do not include the operation
///       requested by the context, the daemon returns
///       CryptoErrorCode::kKeyOperationNotPermitted.
enum class KeyOperationPermission : uint32_t
{
    kNone = 0x0000U,  ///< No operations permitted (storage-only key)

    // ---- Data protection (bits 0–3) ----
    kEncrypt = 0x0001U,  ///< Symmetric/asymmetric encryption
    kDecrypt = 0x0002U,  ///< Symmetric/asymmetric decryption
    kWrap = 0x0004U,     ///< Key wrapping (encrypting another key)
    kUnwrap = 0x0008U,   ///< Key unwrapping (decrypting a wrapped key)

    // ---- Authentication (bits 4–7) ----
    kSign = 0x0010U,    ///< Digital signature generation
    kVerify = 0x0020U,  ///< Digital signature verification
    kMac = 0x0040U,     ///< MAC generation and verification
    kAgree = 0x0080U,   ///< Key agreement (ECDH, ML-KEM decapsulation)

    // ---- Key lifecycle (bits 8–10) ----
    kDerive = 0x0100U,  ///< Key derivation (as source key)
    kExport = 0x0200U,  ///< Export raw key material (for exportable keys)
    kImport = 0x0400U,  ///< Slot accepts imported key material

    // ---- Composite presets (common deployment patterns) ----

    /// Data protection: encrypt + decrypt + wrap + unwrap
    kDataProtection = 0x000FU,
    /// Authentication: sign + verify + mac + agree
    kAuthentication = 0x00F0U,
    /// Full lifecycle: derive + export + import
    kFullLifecycle = 0x0700U,
    /// All operations permitted (no restrictions)
    kAll = 0x07FFU,
};

/// @brief Bitwise OR for combining key operation permissions.
inline constexpr KeyOperationPermission operator|(KeyOperationPermission lhs, KeyOperationPermission rhs) noexcept
{
    return static_cast<KeyOperationPermission>(static_cast<uint32_t>(lhs) | static_cast<uint32_t>(rhs));
}

/// @brief Bitwise AND for testing key operation permissions.
inline constexpr KeyOperationPermission operator&(KeyOperationPermission lhs, KeyOperationPermission rhs) noexcept
{
    return static_cast<KeyOperationPermission>(static_cast<uint32_t>(lhs) & static_cast<uint32_t>(rhs));
}

/// @brief Bitwise NOT for inverting key operation permissions.
/// @note Result is masked to valid permission bits (0–10) to prevent undefined states.
inline constexpr KeyOperationPermission operator~(KeyOperationPermission perm) noexcept
{
    constexpr uint32_t kValidBitsMask = 0x07FFU;  // Bits 0–10 only
    return static_cast<KeyOperationPermission>((~static_cast<uint32_t>(perm)) & kValidBitsMask);
}

/// @brief Bitwise OR-assign for accumulating key operation permissions.
inline constexpr KeyOperationPermission& operator|=(KeyOperationPermission& lhs, KeyOperationPermission rhs) noexcept
{
    lhs = lhs | rhs;
    return lhs;
}

/// @brief Bitwise AND-assign for masking key operation permissions.
inline constexpr KeyOperationPermission& operator&=(KeyOperationPermission& lhs, KeyOperationPermission rhs) noexcept
{
    lhs = lhs & rhs;
    return lhs;
}

/// @brief Tests whether a permission set includes a specific required permission.
/// @param granted The permission set to test (e.g., from KeySlotInfo)
/// @param required The permission(s) being checked
/// @return true if all bits in required are set in granted
inline constexpr bool HasPermission(KeyOperationPermission granted, KeyOperationPermission required) noexcept
{
    // Only consider defined permission bits (bits 0..10). Mask both operands
    // to avoid granting permissions due to out-of-range/invalid bits.
    constexpr uint32_t kValidBitsMask = 0x07FFU;  // bits 0..10
    const uint32_t g = static_cast<uint32_t>(granted) & kValidBitsMask;
    const uint32_t r = static_cast<uint32_t>(required) & kValidBitsMask;
    return (g & r) == r;
}

/// @brief Information about a certificate slot and its contents.
///
/// Returned by ICertificateManagementContext::GetCertificateSlotInfo().
struct CertificateSlotInfo
{
    bool occupied{false};           ///< Whether the slot contains a certificate
    AlgorithmId algorithm{};        ///< Public key algorithm of the stored certificate (empty if unoccupied)
    uint16_t primary_provider{0U};  ///< Provider/device that owns this slot
};

/// @brief Information about a key slot and its contents.
///
/// Returned by IKeyManagementContext::GetKeySlotInfo(). Exposes device binding,
/// cross-provider compatibility, and permitted operations so applications can
/// make informed decisions.
struct KeySlotInfo
{
    KeySlotState state{KeySlotState::kEmpty};  ///< State of the key slot
    AlgorithmId algorithm{};                   ///< Algorithm of the stored key (empty if slot is empty)
    uint16_t primary_provider{0U};             ///< Provider/device that owns this slot

    /// @brief Secondary providers that can also use keys in this slot.
    ///
    /// Fixed-capacity array (max 8 providers). Use compatible_provider_count
    /// to determine how many entries are valid.
    static constexpr std::size_t kMaxCompatibleProviders = 8U;
    std::array<uint16_t, kMaxCompatibleProviders> compatible_providers{};
    std::size_t compatible_provider_count{0U};

    /// @brief Operations this key slot permits.
    ///
    /// Defaults to kAll for backward compatibility. When provisioned with
    /// restricted permissions, the daemon enforces them at context creation
    /// time — creating an encrypt context with a sign-only key returns
    /// CryptoErrorCode::kKeyOperationNotPermitted.
    KeyOperationPermission permitted_operations{KeyOperationPermission::kAll};
};

/// @brief Human-readable provider metadata.
///
/// Returned by ICryptoContext::GetProviderInfo(). Maps daemon-assigned numeric
/// provider IDs to descriptive information.
struct ProviderInfo
{
    uint16_t id{0U};                            ///< Daemon-assigned provider index
    ProviderType type{ProviderType::kDefault};  ///< Provider classification
    FixedCapacityString<32> name{};             ///< Human-readable provider name (e.g., "OpenSSL", "SoftHSM")
};

/// @brief Cross-provider compatibility information for a resource.
///
/// Returned by ICryptoContext::QueryProviderCompatibility(). Secondary providers
/// are those that can also use this resource (e.g., a SW-exported key re-importable
/// into another SW provider). Not embedded in CryptoResourceId because the
/// secondary list is variable-length and mutable daemon-side state.
struct ProviderCompatibilityInfo
{
    CryptoResourceId resource{};    ///< The queried resource
    uint16_t primary_provider{0U};  ///< Owning provider

    /// @brief Providers that can also use this resource.
    ///
    /// Fixed-capacity array (max 8 providers). Use secondary_provider_count
    /// to determine how many entries are valid.
    static constexpr std::size_t kMaxSecondaryProviders = 8U;
    std::array<uint16_t, kMaxSecondaryProviders> secondary_providers{};
    std::size_t secondary_provider_count{0U};
};

/// @brief Capabilities of a specific algorithm as reported by the daemon.
///
/// Returned by ICryptoContext::QueryCapabilities(). Includes PQC algorithms
/// (e.g., "ML-KEM-768", "ML-DSA-65") when supported by configured providers.
struct AlgorithmCapabilities
{
    AlgorithmId id{};       ///< Algorithm identifier
    bool supported{false};  ///< Whether any configured provider supports this algorithm

    /// @brief Supported modes/variants (e.g., "CBC", "GCM", "CTR").
    ///
    /// Fixed-capacity array (max 16 modes). Use mode_count to determine
    /// how many entries are valid.
    static constexpr std::size_t kMaxModes = 16U;
    std::array<FixedCapacityString<16>, kMaxModes> modes{};
    std::size_t mode_count{0U};
};

/// @brief Aggregate view of all providers and supported algorithms.
///
/// Returned by the parameterless ICryptoContext::QueryCapabilities() overload.
/// Provides a complete snapshot of the system's crypto capabilities.
struct SystemCapabilities
{
    /// @brief All configured providers.
    ///
    /// Fixed-capacity array (max 16 providers). Use provider_count to determine
    /// how many entries are valid.
    static constexpr std::size_t kMaxProviders = 16U;
    std::array<ProviderInfo, kMaxProviders> providers{};
    std::size_t provider_count{0U};

    /// @brief All supported algorithms.
    ///
    /// Fixed-capacity array (max 64 algorithms). Use algorithm_count to determine
    /// how many entries are valid.
    static constexpr std::size_t kMaxAlgorithms = 64U;
    std::array<AlgorithmCapabilities, kMaxAlgorithms> algorithms{};
    std::size_t algorithm_count{0U};
};

/// @brief Single key-value entry for algorithm- or operation-scoped extended parameters.
struct ExtendedParameterEntry
{
    FixedCapacityString<32> key{};    ///< Parameter name (middleware-defined, not provider-defined)
    FixedCapacityString<64> value{};  ///< Parameter value
};

/// @brief Fixed-capacity key-value map for algorithm- or operation-scoped extended parameters.
///
/// Provides a forward-compatible extension point in context configs for parameters
/// that are not yet modeled as typed fields (e.g., PQC parameter sets, key-derivation
/// context strings). Keys and their semantics are defined by the **middleware
/// specification** — never by the underlying crypto provider or hardware back-end.
///
/// Provider-specific tuning (HSM slot indices, PIN policies, vendor flags, etc.)
/// belongs exclusively in the daemon's static configuration and must NOT appear
/// here. Application code using this struct must remain portable across all
/// compliant provider implementations.
///
/// Max 16 entries.
struct ExtendedParameters
{
    static constexpr std::size_t kMaxEntries = 16U;
    std::array<ExtendedParameterEntry, kMaxEntries> entries{};
    std::size_t entry_count{0U};
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

/// @brief std::hash specialization for CryptoResourceId, enabling use in unordered containers.
template <>
struct std::hash<score::mw::crypto::CryptoResourceId>
{
    std::size_t operator()(const score::mw::crypto::CryptoResourceId& rid) const noexcept
    {
        std::size_t h = std::hash<uint64_t>{}(rid.id);
        h ^= std::hash<uint8_t>{}(static_cast<uint8_t>(rid.type)) << 1U;
        h ^= std::hash<uint8_t>{}(static_cast<uint8_t>(rid.persistence)) << 2U;
        h ^= std::hash<uint16_t>{}(rid.primary_provider) << 3U;
        return h;
    }
};

#endif  // SCORE_MW_CRYPTO_API_COMMON_TYPES_HPP

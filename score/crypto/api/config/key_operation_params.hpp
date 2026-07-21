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

#ifndef SCORE_MW_CRYPTO_API_CONFIG_KEY_OPERATION_PARAMS_HPP
#define SCORE_MW_CRYPTO_API_CONFIG_KEY_OPERATION_PARAMS_HPP

#include "score/mw/crypto/api/common/types.hpp"
#include "score/span.hpp"

#include <cstdint>
#include <optional>
#include <variant>

namespace score
{
namespace mw
{
namespace crypto
{

// TODO: Check enforcing the builder pattern for config creation.

/// @brief Structured parameters for key derivation functions.
///
// clang-format off
/// | KDF                   | kdf_algorithm         | salt             | label                         | seed                          | output_key_length | iteration_count |
/// |-----------------------|-----------------------|------------------|-------------------------------|-------------------------------|-------------------|-----------------|
/// | HKDF (RFC 5869)       | "HKDF-SHA256"         | Extract salt     | Expand info                   | —                             | Required          | —               |
/// | TLS 1.2 PRF           | "TLS12-PRF-SHA256"    | —                | "master secret"               | client_random ‖ server_random | Required          | —               |
/// |                       |                       |                  | "key expansion"               |                               |                   |                 |
/// | TLS 1.2 EMS           | "TLS12-PRF-SHA256"    | —                | "extended master secret"      | transcript hash               | Required          | —               |
/// | TLS 1.3 HKDF          | "TLS13-HKDF-SHA256"   | —                | "derived" / "c hs traffic"    | transcript hash               | Required          | —               |
/// | PBKDF2 (RFC 8018)     | "PBKDF2-SHA256"       | Password salt    | —                             | —                             | Required          | Required        |
/// | SP800-108 CTR-HMAC    | "SP800-108-CTR-HMAC"  | —                | Label                         | Context                       | Required          | —               |
// clang-format on
///
/// All fields use fixed-capacity types — zero heap allocation.
///
/// @note Validation: Validate() is called automatically by DeriveKeyParams::Validate()
///       and AgreeKeyParams::Validate(), which implementations invoke before IPC dispatch.
struct KdfParameters
{
    /// @brief KDF algorithm identifier (required).
    /// Examples: "HKDF-SHA256", "TLS12-PRF-SHA256", "TLS13-HKDF-SHA256",
    ///           "PBKDF2-SHA256", "SP800-108-CTR-HMAC"
    AlgorithmId kdf_algorithm{};

    /// @brief Salt for HKDF-Extract or PBKDF2. Unused for TLS PRF.
    static constexpr std::size_t kMaxSaltLength = 128U;
    std::array<uint8_t, kMaxSaltLength> salt{};
    std::size_t salt_length{0U};

    /// @brief Label / info string for HKDF-Expand, TLS PRF label, or SP800-108 Label.
    /// Examples: "master secret", "extended master secret", "key expansion",
    ///           "derived", "c hs traffic", "s hs traffic", "c ap traffic"
    FixedCapacityString<128> label{};

    /// @brief Seed / context bytes for TLS PRF seed (client_random || server_random),
    /// TLS 1.3 transcript hash, or SP800-108 Context.
    static constexpr std::size_t kMaxSeedLength = 256U;
    std::array<uint8_t, kMaxSeedLength> seed{};
    std::size_t seed_length{0U};

    /// @brief Desired output key length in bytes.
    /// Required for all KDFs except when the algorithm implies a fixed output size.
    std::optional<uint32_t> output_key_length{std::nullopt};

    /// @brief Iteration count for PBKDF2. Ignored by other KDFs.
    std::optional<uint32_t> iteration_count{std::nullopt};

    // -- Fluent builder --
    // TODO: Check enforcing the builder pattern for config creation.

    KdfParameters& SetKdfAlgorithm(const AlgorithmId& alg) noexcept
    {
        kdf_algorithm = alg;
        return *this;
    }

    KdfParameters& SetSalt(const uint8_t* data, std::size_t len) noexcept
    {
        if (len > kMaxSaltLength)
        {
            truncated_ = true;
            salt_length = kMaxSaltLength;
        }
        else
        {
            salt_length = len;
        }
        for (std::size_t i = 0U; i < salt_length; ++i)
        {
            salt[i] = data[i];
        }
        return *this;
    }

    KdfParameters& SetLabel(const char* lbl) noexcept
    {
        label = FixedCapacityString<128>(lbl);
        if (label.truncated())
        {
            truncated_ = true;
        }
        return *this;
    }

    KdfParameters& SetSeed(const uint8_t* data, std::size_t len) noexcept
    {
        if (len > kMaxSeedLength)
        {
            truncated_ = true;
            seed_length = kMaxSeedLength;
        }
        else
        {
            seed_length = len;
        }
        for (std::size_t i = 0U; i < seed_length; ++i)
        {
            seed[i] = data[i];
        }
        return *this;
    }

    KdfParameters& SetOutputKeyLength(uint32_t len) noexcept
    {
        output_key_length = len;
        return *this;
    }

    KdfParameters& SetIterationCount(uint32_t count) noexcept
    {
        iteration_count = count;
        return *this;
    }

    /// @brief Validates the constructed parameters for consistency and truncation.
    ///
    /// Checks:
    /// - No silent truncation occurred in SetSalt() or SetSeed() — returns
    ///   kParamTruncated. This is the only place this error can be caught:
    ///   the daemon receives a clean fixed-size array and cannot detect truncation.
    /// - KDF algorithm is specified (non-empty) — returns kInvalidArgument.
    ///   This is an advisory early-fail check; the daemon would also reject it.
    ///
    /// @note Calling Validate() before DeriveKey() / AgreeKey() is strongly
    ///       recommended for the truncation check.
    score::Result<std::monostate> Validate() const noexcept
    {
        if (truncated_)
        {
            return score::Result<std::monostate>{score::unexpect, MakeError(CryptoErrorCode::kParamTruncated)};
        }
        if (kdf_algorithm.empty())
        {
            return score::Result<std::monostate>{score::unexpect, MakeError(CryptoErrorCode::kInvalidArgument)};
        }
        return score::Result<std::monostate>{std::monostate{}};
    }

  private:
    /// @brief Tracks if any Set*() call silently truncated input (salt or seed too long).
    bool truncated_{false};
};

/// @brief Parameters for key generation via IKeyManagementContext::GenerateKey().
///
/// Supports both symmetric (AES) and asymmetric (RSA, ECDH, ML-DSA, ML-KEM) algorithms.
/// For asymmetric algorithms, the public key is derived from the private key.
/// Public key permissions and export flags are only meaningful for asymmetric generation.
struct GenerateKeyParams
{
    /// @brief Algorithm identifier for the key to generate (required).
    /// Examples: "AES-256", "RSA-2048", "ECDH-P256", "ML-KEM-768", "ML-DSA-65"
    AlgorithmId algorithm{};

    /// @brief Operations the generated key is permitted to perform.
    /// For symmetric keys: controls encrypt/decrypt/wrap/unwrap permissions.
    /// For asymmetric keys: controls permissions of the private key (sign/decrypt/agree).
    /// Defaults to kAll (no restrictions). The daemon enforces permissions
    /// at context creation time.
    KeyOperationPermission permissions{KeyOperationPermission::kAll};

    /// @brief Operations the public key is permitted to perform (asymmetric only).
    /// When set (not std::nullopt), controls public key usage (verify/encrypt).
    /// Use kExport bit to control public key exportability.
    /// When omitted (default std::nullopt), public key inherits full permissions.
    /// Only meaningful when algorithm is asymmetric.
    std::optional<KeyOperationPermission> public_key_permissions{std::nullopt};

    // -- Fluent builder --

    GenerateKeyParams& SetAlgorithm(const AlgorithmId& alg) noexcept
    {
        algorithm = alg;
        return *this;
    }

    GenerateKeyParams& SetPermissions(KeyOperationPermission perms) noexcept
    {
        permissions = perms;
        return *this;
    }

    GenerateKeyParams& SetPublicKeyPermissions(KeyOperationPermission perms) noexcept
    {
        public_key_permissions = perms;
        return *this;
    }
};

/// @brief Parameters for key derivation via IKeyManagementContext::DeriveKey().
///
/// Supports HKDF, TLS 1.2 PRF, TLS 1.3 HKDF, PBKDF2, and SP800-108
/// via the structured KdfParameters field.
struct DeriveKeyParams
{
    /// @brief Handle to the source key (required). CryptoResourceId with type = kKey.
    CryptoResourceId source_key{};

    /// @brief Algorithm identifier for the derived key (required).
    /// Determines the type and length of the output key.
    AlgorithmId derived_key_algorithm{};

    /// @brief KDF parameters: algorithm, salt, label, seed, output length (required).
    KdfParameters kdf{};

    /// @brief Operations the derived key is permitted to perform.
    KeyOperationPermission permissions{KeyOperationPermission::kAll};

    // -- Fluent builder --

    DeriveKeyParams& SetSourceKey(const CryptoResourceId& key) noexcept
    {
        source_key = key;
        return *this;
    }

    DeriveKeyParams& SetDerivedKeyAlgorithm(const AlgorithmId& alg) noexcept
    {
        derived_key_algorithm = alg;
        return *this;
    }

    DeriveKeyParams& SetKdf(const KdfParameters& params) noexcept
    {
        kdf = params;
        return *this;
    }

    DeriveKeyParams& SetPermissions(KeyOperationPermission perms) noexcept
    {
        permissions = perms;
        return *this;
    }

    /// @brief Validates these parameters.
    ///
    /// Propagates KdfParameters::Validate() — in particular, catches truncation
    /// that occurred in SetSalt() or SetSeed().
    score::Result<std::monostate> Validate() const noexcept
    {
        return kdf.Validate();
    }
};

/// @brief Parameters for key agreement via IKeyManagementContext::AgreeKey().
///
/// Supports raw key agreement (ECDH, X25519, ML-KEM decapsulation) and
/// combined agree-then-derive (ECIES, TLS key exchange) when kdf is set.
struct AgreeKeyParams
{
    /// @brief Handle to this party's private key (required).
    CryptoResourceId private_key{};

    /// @brief The other party's public key data (required).
    /// Points to caller-owned memory — must remain valid until the call returns.
    score::cpp::span<const uint8_t> peer_public_key{};

    /// @brief Key agreement algorithm (required).
    /// Examples: "ECDH-P256", "X25519", "ML-KEM-768"
    AlgorithmId agreement_algorithm{};

    /// @brief Format of the peer public key data. Defaults to raw/uncompressed.
    std::optional<FormatType> public_key_format{std::nullopt};

    /// @brief Algorithm for the output key when KDF is used (optional).
    /// When set together with kdf, the daemon shall perform agreement + KDF atomically.
    /// When omitted (and kdf is omitted), the raw shared secret is returned.
    std::optional<AlgorithmId> derived_key_algorithm{std::nullopt};

    /// @brief KDF parameters for combined agree-then-derive (optional).
    /// When set, the raw shared secret is fed through the KDF before being
    /// returned as a key of type derived_key_algorithm.
    std::optional<KdfParameters> kdf{std::nullopt};

    /// @brief Operations the agreed/derived key is permitted to perform.
    KeyOperationPermission permissions{KeyOperationPermission::kAll};

    // -- Fluent builder --

    AgreeKeyParams& SetPrivateKey(const CryptoResourceId& key) noexcept
    {
        private_key = key;
        return *this;
    }

    AgreeKeyParams& SetPeerPublicKey(score::cpp::span<const uint8_t> data) noexcept
    {
        peer_public_key = data;
        return *this;
    }

    AgreeKeyParams& SetAgreementAlgorithm(const AlgorithmId& alg) noexcept
    {
        agreement_algorithm = alg;
        return *this;
    }

    AgreeKeyParams& SetPublicKeyFormat(FormatType fmt) noexcept
    {
        public_key_format = fmt;
        return *this;
    }

    AgreeKeyParams& SetDerivedKeyAlgorithm(const AlgorithmId& alg) noexcept
    {
        derived_key_algorithm = alg;
        return *this;
    }

    AgreeKeyParams& SetKdf(const KdfParameters& params) noexcept
    {
        kdf = params;
        return *this;
    }

    AgreeKeyParams& SetPermissions(KeyOperationPermission perms) noexcept
    {
        permissions = perms;
        return *this;
    }

    /// @brief Validates these parameters before dispatch to the daemon.
    ///
    /// When kdf is set, propagates KdfParameters::Validate() to catch truncation
    /// that occurred in SetSalt() or SetSeed().
    score::Result<std::monostate> Validate() const noexcept
    {
        if (kdf.has_value())
        {
            return kdf->Validate();
        }
        return score::Result<std::monostate>{std::monostate{}};
    }
};

/// @brief Parameters for key wrapping via IKeyManagementContext::WrapKey().
struct WrapKeyParams
{
    /// @brief Handle to the key to wrap (required).
    CryptoResourceId key_to_wrap{};

    /// @brief Handle to the wrapping key / KEK (required).
    CryptoResourceId wrapping_key{};

    /// @brief Wrapping algorithm (optional). When omitted, the daemon selects
    /// based on the wrapping key's algorithm (e.g., AES-KEYWRAP for AES keys).
    std::optional<AlgorithmId> wrapping_algorithm{std::nullopt};

    /// @brief Initialization vector for wrapping algorithms that require one
    /// (e.g., AES-GCM, AES-CBC). Points to caller-owned memory.
    score::cpp::span<const uint8_t> iv{};

    /// @brief Additional authenticated data for AEAD wrapping algorithms
    /// (e.g., AES-GCM). Points to caller-owned memory.
    score::cpp::span<const uint8_t> aad{};

    // -- Fluent builder --

    WrapKeyParams& SetKeyToWrap(const CryptoResourceId& key) noexcept
    {
        key_to_wrap = key;
        return *this;
    }

    WrapKeyParams& SetWrappingKey(const CryptoResourceId& key) noexcept
    {
        wrapping_key = key;
        return *this;
    }

    WrapKeyParams& SetWrappingAlgorithm(const AlgorithmId& alg) noexcept
    {
        wrapping_algorithm = alg;
        return *this;
    }

    WrapKeyParams& SetIv(const uint8_t* data, std::size_t len) noexcept
    {
        iv = {data, len};
        return *this;
    }

    WrapKeyParams& SetIv(score::cpp::span<const uint8_t> data) noexcept
    {
        iv = data;
        return *this;
    }

    WrapKeyParams& SetAad(const uint8_t* data, std::size_t len) noexcept
    {
        aad = {data, len};
        return *this;
    }

    WrapKeyParams& SetAad(score::cpp::span<const uint8_t> data) noexcept
    {
        aad = data;
        return *this;
    }
};

/// @brief Parameters for key unwrapping via IKeyManagementContext::UnwrapKey().
struct UnwrapKeyParams
{
    /// @brief Wrapped key blob (required). Points to caller-owned memory.
    score::cpp::span<const uint8_t> wrapped_data{};

    /// @brief Handle to the wrapping key / KEK (required).
    CryptoResourceId wrapping_key{};

    /// @brief Algorithm of the inner (unwrapped) key (required).
    AlgorithmId inner_key_algorithm{};

    /// @brief Wrapping algorithm (optional — same as WrapKeyParams).
    std::optional<AlgorithmId> wrapping_algorithm{std::nullopt};

    /// @brief IV used during wrapping (required for AES-GCM/CBC wrapping).
    score::cpp::span<const uint8_t> iv{};

    /// @brief AAD used during wrapping (for AEAD wrapping algorithms).
    score::cpp::span<const uint8_t> aad{};

    /// @brief Operations the unwrapped key is permitted to perform.
    KeyOperationPermission permissions{KeyOperationPermission::kAll};

    // -- Fluent builder --

    UnwrapKeyParams& SetWrappedData(const uint8_t* data, std::size_t len) noexcept
    {
        wrapped_data = {data, len};
        return *this;
    }

    UnwrapKeyParams& SetWrappedData(score::cpp::span<const uint8_t> data) noexcept
    {
        wrapped_data = data;
        return *this;
    }

    UnwrapKeyParams& SetWrappingKey(const CryptoResourceId& key) noexcept
    {
        wrapping_key = key;
        return *this;
    }

    UnwrapKeyParams& SetInnerKeyAlgorithm(const AlgorithmId& alg) noexcept
    {
        inner_key_algorithm = alg;
        return *this;
    }

    UnwrapKeyParams& SetWrappingAlgorithm(const AlgorithmId& alg) noexcept
    {
        wrapping_algorithm = alg;
        return *this;
    }

    UnwrapKeyParams& SetIv(const uint8_t* data, std::size_t len) noexcept
    {
        iv = {data, len};
        return *this;
    }

    UnwrapKeyParams& SetIv(score::cpp::span<const uint8_t> data) noexcept
    {
        iv = data;
        return *this;
    }

    UnwrapKeyParams& SetAad(const uint8_t* data, std::size_t len) noexcept
    {
        aad = {data, len};
        return *this;
    }

    UnwrapKeyParams& SetAad(score::cpp::span<const uint8_t> data) noexcept
    {
        aad = data;
        return *this;
    }

    UnwrapKeyParams& SetPermissions(KeyOperationPermission perms) noexcept
    {
        permissions = perms;
        return *this;
    }
};

/// @brief Parameters for key import via IKeyManagementContext::ImportKey().
///
/// Intended primarily for importing **public keys** (e.g., a peer's SubjectPublicKeyInfo
/// for signature verification or asymmetric encryption). Public keys carry no
/// confidentiality requirement and DER/PEM are their natural wire formats.
///
/// @warning Importing plaintext private or symmetric key material via this struct
/// is strongly discouraged — it exposes secret material outside the secure boundary.
/// Use UnwrapKey() instead, which accepts the key already encrypted under a KEK
/// and never exposes the plaintext secret.
struct ImportKeyParams
{
    /// @brief Key data to import (required). Points to caller-owned memory.
    /// For public keys: DER-encoded SubjectPublicKeyInfo or PEM equivalent.
    score::cpp::span<const uint8_t> key_data{};

    /// @brief Encoding format of key_data: DER (binary ASN.1) or PEM (base64-armored).
    /// Both formats are meaningful only for asymmetric (public) keys.
    /// Symmetric keys have no ASN.1 structure and must not be imported via this struct.
    FormatType format{FormatType::kDer};

    /// @brief Algorithm identifier for the imported key (required).
    AlgorithmId algorithm{};

    /// @brief Operations the imported key is permitted to perform.
    KeyOperationPermission permissions{KeyOperationPermission::kAll};

    // -- Fluent builder --

    ImportKeyParams& SetKeyData(const uint8_t* data, std::size_t len) noexcept
    {
        key_data = {data, len};
        return *this;
    }

    ImportKeyParams& SetKeyData(score::cpp::span<const uint8_t> data) noexcept
    {
        key_data = data;
        return *this;
    }

    ImportKeyParams& SetFormat(FormatType fmt) noexcept
    {
        format = fmt;
        return *this;
    }

    ImportKeyParams& SetAlgorithm(const AlgorithmId& alg) noexcept
    {
        algorithm = alg;
        return *this;
    }

    ImportKeyParams& SetPermissions(KeyOperationPermission perms) noexcept
    {
        permissions = perms;
        return *this;
    }
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_CONFIG_KEY_OPERATION_PARAMS_HPP

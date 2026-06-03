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

#ifndef SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_KEY_TYPES_HPP
#define SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_KEY_TYPES_HPP

#include "score/crypto/daemon/common/types.hpp"
#include "score/mw/crypto/api/common/types.hpp"
#include "score/mw/crypto/api/config/key_operation_params.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace score::crypto::daemon::key_management
{

// ---------------------------------------------------------------------------
// ProviderKeyHandle — opaque per-key runtime reference
// ---------------------------------------------------------------------------

/// Runtime reference to key material held by a specific provider.
///
/// The opaque_id is allocated, interpreted, and freed exclusively by the
/// provider that issued the handle.  Callers must not dereference or
/// arithmetic-shift opaque_id.
///
///   OpenSSL  : opaque_id maps to raw key bytes managed by the factory
///   PKCS#11  : opaque_id maps to (CK_SESSION_HANDLE, CK_OBJECT_HANDLE)
///   TEE/PSA  : opaque_id = persistent key identifier from the TEE driver
struct ProviderKeyHandle
{
    std::uint64_t opaque_id{0U};
    common::ProviderId provider_id{common::kInvalidProviderId};
    bool is_asymmetric{false};
    score::mw::crypto::KeyOperationPermission permissions{score::mw::crypto::KeyOperationPermission::kNone};
    common::AlgorithmId algorithm{};
    std::size_t key_size{0U};
};

// ---------------------------------------------------------------------------
// Request parameter structs
// ---------------------------------------------------------------------------

/// Parameters for ephemeral symmetric or asymmetric key generation.
struct KeyGenerationRequest
{
    common::AlgorithmId algorithm{};
    score::mw::crypto::KeyOperationPermission permissions{score::mw::crypto::KeyOperationPermission::kAll};
    /// @brief Operations the public key is permitted to perform (asymmetric only).
    /// Use kExport bit to control public key exportability.
    std::optional<score::mw::crypto::KeyOperationPermission> public_key_permissions{std::nullopt};
    score::mw::crypto::ExtendedParameters provider_properties{};
};

/// Parameters for raw key material import.
///
/// key_data points to caller-owned memory that remains valid for the
/// duration of the call only. The callee must copy the bytes.
struct KeyImportRequest
{
    const std::uint8_t* key_data{nullptr};
    std::size_t key_data_size{0U};
    common::AlgorithmId algorithm{};
    score::mw::crypto::FormatType format{score::mw::crypto::FormatType::kDer};
    score::mw::crypto::KeyOperationPermission permissions{score::mw::crypto::KeyOperationPermission::kAll};
    score::mw::crypto::ExtendedParameters provider_properties{};
};

/// Parameters for key derivation (HKDF, PBKDF2, TLS 1.3 KDF, etc.).
///
/// Uses the same KdfParameters as the client API to avoid a double
/// flattened/structured translation layer inside the daemon.
struct KeyDeriveRequest
{
    ProviderKeyHandle base_key{};
    common::AlgorithmId output_algorithm{};
    score::mw::crypto::KdfParameters kdf{};
    score::mw::crypto::KeyOperationPermission permissions{score::mw::crypto::KeyOperationPermission::kAll};
};

/// Parameters for key agreement (ECDH, X25519, ML-KEM).
///
/// When kdf is set, the provider performs agree-then-derive atomically,
/// matching AgreeKeyParams semantics from the client API.
struct KeyAgreeRequest
{
    ProviderKeyHandle private_key{};
    const std::uint8_t* peer_public_key{nullptr};
    std::size_t peer_public_key_size{0U};
    /// Agreement mechanism (e.g., "ECDH", "X25519").
    common::AlgorithmId agreement_algorithm{};
    /// Algorithm of the agreed or derived output key.
    common::AlgorithmId output_algorithm{};
    /// @brief Format of the peer public key data. Defaults to raw/uncompressed.
    std::optional<score::mw::crypto::FormatType> public_key_format{std::nullopt};
    score::mw::crypto::KeyOperationPermission permissions{score::mw::crypto::KeyOperationPermission::kAll};
    /// Optional KDF for combined agree-then-derive (e.g., ECIES, TLS key exchange).
    std::optional<score::mw::crypto::KdfParameters> kdf{std::nullopt};
};

// ---------------------------------------------------------------------------
// WrapKeyRequest / UnwrapKeyRequest — provider-level wrap/unwrap parameters
// ---------------------------------------------------------------------------

/// Parameters for wrapping one key under another (provider level).
///
/// Both handles are ProviderKeyHandles already held by the same provider.
/// Cross-provider wrap is not supported; both keys must be in the same provider.
struct WrapKeyRequest
{
    ProviderKeyHandle key_to_wrap{};
    ProviderKeyHandle wrapping_key{};
    std::optional<common::AlgorithmId> wrapping_algorithm{std::nullopt};
    const std::uint8_t* iv{nullptr};
    std::size_t iv_size{0U};
    const std::uint8_t* aad{nullptr};
    std::size_t aad_size{0U};
};

/// Parameters for unwrapping a wrapped key blob (provider level).
///
/// key_data / key_data_size point to caller-owned memory valid for the call.
struct UnwrapKeyRequest
{
    const std::uint8_t* wrapped_data{nullptr};
    std::size_t wrapped_data_size{0U};
    ProviderKeyHandle wrapping_key{};
    common::AlgorithmId inner_key_algorithm{};
    std::optional<common::AlgorithmId> wrapping_algorithm{std::nullopt};
    const std::uint8_t* iv{nullptr};
    std::size_t iv_size{0U};
    const std::uint8_t* aad{nullptr};
    std::size_t aad_size{0U};
    score::mw::crypto::KeyOperationPermission permissions{score::mw::crypto::KeyOperationPermission::kAll};
};

// ---------------------------------------------------------------------------
// SecureKeyBytes — RAII container for exported key material
// ---------------------------------------------------------------------------

/// Bytes are securely zeroized on destruction.
///
/// Ephemeral keys remain associated with their creating provider for the
/// duration of the context. Must not be stored in persistent data structures.
struct SecureKeyBytes
{
    std::vector<std::uint8_t> bytes;

    SecureKeyBytes() = default;
    explicit SecureKeyBytes(std::size_t size) : bytes(size) {}

    ~SecureKeyBytes()
    {
        for (auto& b : bytes)
        {
            b = 0U;
        }
    }

    SecureKeyBytes(const SecureKeyBytes&) = delete;
    SecureKeyBytes& operator=(const SecureKeyBytes&) = delete;
    SecureKeyBytes(SecureKeyBytes&&) noexcept = default;
    SecureKeyBytes& operator=(SecureKeyBytes&&) noexcept = default;
};

// ---------------------------------------------------------------------------
// Well-known operation constants
// ---------------------------------------------------------------------------

}  // namespace score::crypto::daemon::key_management

#endif  // SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_KEY_TYPES_HPP

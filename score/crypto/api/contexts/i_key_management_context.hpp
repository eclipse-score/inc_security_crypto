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

#ifndef SCORE_MW_CRYPTO_API_CONTEXTS_I_KEY_MANAGEMENT_CONTEXT_HPP
#define SCORE_MW_CRYPTO_API_CONTEXTS_I_KEY_MANAGEMENT_CONTEXT_HPP

#include "score/mw/crypto/api/common/crypto_resource_guard.hpp"
#include "score/mw/crypto/api/common/types.hpp"
#include "score/mw/crypto/api/config/key_operation_params.hpp"
#include "score/mw/crypto/api/contexts/i_context.hpp"
#include "score/result/result.h"
#include "score/span.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>

namespace score
{
namespace mw
{
namespace crypto
{

/// @brief Interface for key lifecycle management operations.
///
/// All key-producing methods return a CryptoResourceGuard that owns the
/// ephemeral key resource. The guard releases it to the daemon when it
/// goes out of scope, ensuring keys are never silently leaked.
///
/// The guard provides implicit conversion to `const CryptoResourceId&`,
/// so it can be passed directly to SetKey(), ExportKey(), PersistKey(),
/// and any other API that accepts CryptoResourceId — no explicit .Id() call.
///
/// All key-producing operations (GenerateKey, DeriveKey, AgreeKey, UnwrapKey,
/// ImportKey) provide two overloads:
///
///   - **Ephemeral overload** — takes only a params struct, returns a
///     CryptoResourceGuard wrapping the ephemeral key. The guard provides
///     RAII cleanup: daemon frees key material when the guard is destroyed.
///
///   - **Direct-to-slot overload** — takes a target_slot CryptoResourceId as
///     the first parameter followed by the params struct, returns Result<std::monostate>.
///     The key is generated/derived/imported directly into the persistent slot.
///     No guard is involved — the key lives in the slot and is accessed via
///     the slot-direct path.
///
/// Each operation's parameters are encapsulated in a dedicated params struct
/// with a fluent builder API (e.g., GenerateKeyParams, DeriveKeyParams).
/// Key derivation uses structured KdfParameters with typed fields,
/// supporting HKDF, TLS 1.2 PRF, TLS 1.3 HKDF, PBKDF2, and SP800-108.
///
/// Two key usage paths after creation:
/// - **Slot-direct**: Pass a resolved kKeySlot directly to config.SetKey().
///   The context factory internally loads key material and releases it on
///   context destruction. No LoadKey() or guard needed.
/// - **Guard path**: Call LoadKey()/GenerateKey()/etc. to get a guard.
///   The guard auto-releases on destruction. Use this when sharing the
///   same loaded key across multiple contexts (performance optimization).
///
/// Supports classical key types (AES, RSA, ECC) and PQC key types:
/// - ML-KEM (Kyber) for key encapsulation
/// - ML-DSA (Dilithium) for signatures
/// - SLH-DSA (SPHINCS+) for stateless hash-based signatures
/// - XMSS/LMS for stateful hash-based signatures
///
/// PQC key generation may produce larger keys — call GetExportKeySize()
/// before ExportKey() to determine the required buffer size.
class IKeyManagementContext : public IContext
{
  public:
    using Uptr = std::unique_ptr<IKeyManagementContext>;

    ~IKeyManagementContext() override = default;

    IKeyManagementContext(const IKeyManagementContext&) = delete;
    IKeyManagementContext& operator=(const IKeyManagementContext&) = delete;
    IKeyManagementContext(IKeyManagementContext&&) = default;
    IKeyManagementContext& operator=(IKeyManagementContext&&) = default;

    // =========================================================================
    // Key Generation
    // =========================================================================

    /// @brief Generates a new ephemeral key (symmetric or asymmetric).
    ///
    /// For symmetric algorithms (AES), returns a single symmetric key.
    /// For asymmetric algorithms (RSA, ECDH, ML-DSA, etc.), returns the private key.
    /// The public key can be derived on-demand via IPrivateKeyObject::GetPublicKey().
    ///
    /// @param params Key generation parameters (algorithm, permissions).
    /// @return CryptoResourceGuard wrapping the ephemeral key (symmetric or private).
    virtual score::Result<CryptoResourceGuard> GenerateKey(const GenerateKeyParams& params) = 0;

    /// @brief Generates a key directly into a persistent key slot.
    ///
    /// For symmetric algorithms, occupies only the target_slot.
    /// For asymmetric algorithms, occupies target_slot (private) and optionally
    /// public_slot (public key). If public_slot is omitted, the public key
    /// remains ephemeral and must be derived when needed.
    ///
    /// @param target_slot Handle to the target key slot (type = kKeySlot).
    ///                     For asymmetric: holds private key.
    ///                     For symmetric: holds the symmetric key.
    /// @param public_slot Optional second slot for public key (asymmetric only).
    ///                    Ignored for symmetric algorithms. If provided for asymmetric,
    ///                    the public key is generated directly into this slot.
    /// @param params Key generation parameters (algorithm, permissions).
    /// @return std::monostate on success; error if slot is occupied, policy violation, etc.
    virtual score::Result<std::monostate> GenerateKey(const CryptoResourceId& target_slot,
                                                      const std::optional<CryptoResourceId>& public_slot,
                                                      const GenerateKeyParams& params) = 0;

    // =========================================================================
    // Key Derivation
    // =========================================================================

    /// @brief Derives a new ephemeral key using structured KDF parameters.
    /// @param params Derivation parameters (source key, algorithm, KDF config, permissions).
    ///              Implementations shall call params.Validate() before IPC dispatch to catch
    ///              KDF truncation errors.
    /// @return CryptoResourceGuard wrapping the ephemeral derived key.
    /// @see KdfParameters for supported KDFs (HKDF, TLS 1.2 PRF, TLS 1.3, PBKDF2, SP800-108).
    virtual score::Result<CryptoResourceGuard> DeriveKey(const DeriveKeyParams& params) = 0;

    /// @brief Derives a key directly into a persistent key slot.
    /// @param target_slot Handle to the target key slot (type = kKeySlot).
    /// @param params Derivation parameters. Implementations shall call params.Validate().
    /// @return std::monostate on success.
    virtual score::Result<std::monostate> DeriveKey(const CryptoResourceId& target_slot,
                                                    const DeriveKeyParams& params) = 0;

    // =========================================================================
    // Key Agreement
    // =========================================================================

    /// @brief Performs key agreement (ECDH, X25519, ML-KEM decapsulation).
    ///
    /// When AgreeKeyParams::kdf is set, the daemon shall perform agreement + KDF
    /// atomically in a single IPC call, returning the derived key directly.
    /// When kdf is omitted, the raw shared secret is returned.
    ///
    /// @param params Agreement parameters (private key, peer public key,
    ///        agreement algorithm, optional KDF for combined agree+derive).
    ///        Implementations shall call params.Validate() before IPC dispatch to catch
    ///        KDF truncation errors.
    /// @return CryptoResourceGuard wrapping the agreed/derived key.
    virtual score::Result<CryptoResourceGuard> AgreeKey(const AgreeKeyParams& params) = 0;

    /// @brief Performs key agreement directly into a persistent key slot.
    /// @param target_slot Handle to the target key slot (type = kKeySlot).
    /// @param params Agreement parameters. Implementations shall call params.Validate() before IPC dispatch.
    /// @return std::monostate on success.
    virtual score::Result<std::monostate> AgreeKey(const CryptoResourceId& target_slot,
                                                   const AgreeKeyParams& params) = 0;

    // =========================================================================
    // Persistence
    // =========================================================================

    /// @brief Copies an ephemeral key to a persistent key slot.
    ///
    /// The ephemeral key (and its guard) remains valid after this call and is
    /// released independently when the guard goes out of scope. Use the guard's
    /// implicit conversion to pass it directly:
    ///
    /// @param target_slot Handle to the target persistent key slot (type = kKeySlot).
    /// @param ephemeral_key CryptoResourceId of the ephemeral key (type = kKey).
    /// @return std::monostate on success, error if not allowed by policy or slot is occupied.
    virtual score::Result<std::monostate> PersistKey(const CryptoResourceId& target_slot,
                                                     const CryptoResourceId& ephemeral_key) = 0;

    // =========================================================================
    // Key Unwrapping
    // =========================================================================

    /// @brief Unwraps (decrypts) a wrapped key blob into an ephemeral key.
    /// @param params Unwrap parameters (wrapped data, wrapping key, inner key algorithm,
    ///        optional wrapping algorithm, IV, AAD, permissions).
    /// @return CryptoResourceGuard wrapping the ephemeral unwrapped key.
    virtual score::Result<CryptoResourceGuard> UnwrapKey(const UnwrapKeyParams& params) = 0;

    /// @brief Unwraps a key directly into a persistent key slot.
    /// @param target_slot Handle to the target key slot (type = kKeySlot).
    /// @param params Unwrap parameters.
    /// @return std::monostate on success.
    virtual score::Result<std::monostate> UnwrapKey(const CryptoResourceId& target_slot,
                                                    const UnwrapKeyParams& params) = 0;

    // =========================================================================
    // Key Import
    // =========================================================================

    /// @brief Imports key data into an ephemeral key.
    /// @param params Import parameters (key data, format, algorithm, permissions).
    /// @return CryptoResourceGuard wrapping the ephemeral imported key.
    virtual score::Result<CryptoResourceGuard> ImportKey(const ImportKeyParams& params) = 0;

    /// @brief Imports key data directly into a persistent key slot.
    /// @param target_slot Handle to the target key slot (type = kKeySlot).
    /// @param params Import parameters.
    /// @return std::monostate on success.
    virtual score::Result<std::monostate> ImportKey(const CryptoResourceId& target_slot,
                                                    const ImportKeyParams& params) = 0;

    // =========================================================================
    // Key Loading (optional — advanced path for multi-context reuse)
    // =========================================================================

    /// @brief Loads a persistent key from a key slot for use in operations.
    /// @param slot Handle to the persistent key slot (type = kKeySlot).
    /// @return CryptoResourceGuard wrapping the loaded key.
    ///
    /// @note LoadKey is optional. The simpler slot-direct path passes a kKeySlot
    ///       directly to config.SetKey(); the context factory loads internally.
    virtual score::Result<CryptoResourceGuard> LoadKey(const CryptoResourceId& slot) = 0;

    // =========================================================================
    // Key Wrapping
    // =========================================================================

    /// @brief Wraps (encrypts) a key using a wrapping key.
    ///
    /// @param params Wrap parameters (key to wrap, wrapping key, optional algorithm/IV/AAD).
    /// @param output Buffer to receive the wrapped key data.
    /// @return Number of bytes written on success.
    virtual score::Result<std::size_t> WrapKey(const WrapKeyParams& params, score::cpp::span<uint8_t> output) = 0;

    /// @brief Returns the byte length of the wrapped form of a key.
    ///
    /// Call this before WrapKey() to allocate a buffer of the correct size.
    /// The size depends on the wrapping algorithm (e.g., AES key wrap adds
    /// 8 bytes of overhead per RFC 3394).
    ///
    /// @param params Wrap parameters (key to wrap, wrapping key, optional algorithm/IV/AAD).
    /// @return Required buffer size in bytes, or error if wrapping is not permitted
    virtual score::Result<std::size_t> GetWrapKeySize(const WrapKeyParams& params) = 0;

    // =========================================================================
    // Key Export
    // =========================================================================

    /// @brief Exports key data in the specified format.
    /// @param key Handle to the key to export.
    /// @param output Buffer to receive the exported key data.
    /// @param format Output encoding format (default: DER).
    /// @return Number of bytes written on success, error if key is not exportable.
    virtual score::Result<std::size_t> ExportKey(const CryptoResourceId& key,
                                                 score::cpp::span<uint8_t> output,
                                                 FormatType format = FormatType::kDer) = 0;

    /// @brief Returns the byte length of the exported form of a key.
    ///
    /// Call this before ExportKey() to allocate a buffer of the correct size.
    /// The size depends on the algorithm and export format (e.g., DER-encoded
    /// PKCS#8 for private keys, SubjectPublicKeyInfo for public keys).
    ///
    /// @param key Handle to the key to query
    /// @param format Desired export format (default: DER)
    /// @return Required buffer size in bytes, or error if the key is not exportable
    virtual score::Result<std::size_t> GetExportKeySize(const CryptoResourceId& key,
                                                        FormatType format = FormatType::kDer) = 0;

    // =========================================================================
    // Key Clearing
    // =========================================================================

    /// @brief Clears a key or key slot.
    /// @param key Handle to the key or key slot to clear.
    /// @return std::monostate on success.
    virtual score::Result<std::monostate> ClearKey(const CryptoResourceId& key) = 0;

    // =========================================================================
    // Slot Queries
    // =========================================================================

    /// @brief Queries the state and metadata of a key slot.
    /// @param slot Handle to the key slot (type = kKeySlot).
    /// @return KeySlotInfo containing state, algorithm, and provider binding.
    virtual score::Result<KeySlotInfo> GetKeySlotInfo(const CryptoResourceId& slot) = 0;

  protected:
    IKeyManagementContext() = default;
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_CONTEXTS_I_KEY_MANAGEMENT_CONTEXT_HPP

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

/// @file pqc_provider_ffi.h
/// @brief Stable C ABI between the C++ daemon and the Rust PQC backend.

#ifndef SCORE_PQC_PROVIDER_FFI_H
#define SCORE_PQC_PROVIDER_FFI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// @brief Status codes returned by the PQC Provider C ABI.
///
/// The numeric values are part of the stable ABI and must not be changed.
typedef enum pqc_provider_status
{
    PqcProviderStatusOk = 0,                    ///< The operation completed successfully.
    PqcProviderStatusInvalidArgument = 1,       ///< One or more arguments are invalid.
    PqcProviderStatusBufferTooSmall = 2,        ///< An output buffer cannot hold the result.
    PqcProviderStatusUnsupportedAlgorithm = 3,  ///< The requested algorithm is not supported.
    PqcProviderStatusVerificationFailed = 4,    ///< Verification completed and the signature is invalid.
    PqcProviderStatusCryptoFailure = 5          ///< The backend failed to perform the cryptographic operation.
} pqc_provider_status;

/// @brief Algorithms understood by the PQC Provider C ABI.
///
/// The numeric values are part of the stable ABI and must not be changed.
typedef enum pqc_provider_algorithm
{
    PqcProviderAlgorithmMlDsa44 = 1,    ///< ML-DSA-44 signature algorithm.
    PqcProviderAlgorithmMlDsa65 = 2,    ///< ML-DSA-65 signature algorithm.
    PqcProviderAlgorithmMlDsa87 = 3,    ///< ML-DSA-87 signature algorithm.
    PqcProviderAlgorithmMlKem512 = 10,  ///< ML-KEM-512 key-encapsulation algorithm.
    PqcProviderAlgorithmMlKem768 = 11,  ///< ML-KEM-768 key-encapsulation algorithm.
    PqcProviderAlgorithmMlKem1024 = 12  ///< ML-KEM-1024 key-encapsulation algorithm.
} pqc_provider_algorithm;

/// @brief Opaque backend-owned key handle.
///
/// The handle contents are private to the backend and must not be inspected
/// or modified by callers. Handles returned by generation functions must be
/// released with pqc_provider_key_destroy().
typedef struct pqc_provider_key_handle pqc_provider_key_handle;

// ---------------------------------------------------------------------------
// Signature key management
// ---------------------------------------------------------------------------

/// @brief Generate a signature key pair.
///
/// @param algorithm Signature algorithm to use.
/// @param key Output pointer receiving the generated key handle.
/// @return PqcProviderStatusOk on success, or an error status if generation fails.
pqc_provider_status pqc_provider_keypair_generate(pqc_provider_algorithm algorithm, pqc_provider_key_handle** key);

/// @brief Export the public key associated with a signature key handle.
///
/// @param key Signature key handle owned by the caller.
/// @param output Caller-provided output buffer for the public key.
/// @param output_len Input buffer capacity and output length written.
/// @return PqcProviderStatusOk on success, PqcProviderStatusBufferTooSmall when the
///         output buffer is insufficient, or another error status.
pqc_provider_status pqc_provider_public_key_export(const pqc_provider_key_handle* key, uint8_t* output, size_t* output_len);

// ---------------------------------------------------------------------------
// Signature operations
// ---------------------------------------------------------------------------

/// @brief Sign a message with a generated signature key.
///
/// @param key Signature key handle owned by the caller.
/// @param message Message data to sign.
/// @param message_len Number of bytes in message.
/// @param signature Caller-provided output buffer for the signature.
/// @param signature_len Input buffer capacity and output signature length.
/// @return PqcProviderStatusOk on success, PqcProviderStatusBufferTooSmall when the
///         signature buffer is insufficient, or another error status.
pqc_provider_status pqc_provider_sign(const pqc_provider_key_handle* key,
                    const uint8_t* message,
                    size_t message_len,
                    uint8_t* signature,
                    size_t* signature_len);

/// @brief Verify a message signature.
///
/// @param key Signature key handle owned by the caller.
/// @param message Message data to verify.
/// @param message_len Number of bytes in message.
/// @param signature Signature to verify.
/// @param signature_len Number of bytes in signature.
/// @return PqcProviderStatusOk when the signature is valid,
///         PqcProviderStatusVerificationFailed when it is invalid, or another
///         error status when verification cannot be performed.
pqc_provider_status pqc_provider_verify(const pqc_provider_key_handle* key,
                      const uint8_t* message,
                      size_t message_len,
                      const uint8_t* signature,
                      size_t signature_len);

/// @brief Verify a message signature using an imported public key.
///
/// @param algorithm Signature algorithm to use.
/// @param public_key Raw public key used for verification.
/// @param public_key_len Number of bytes in public_key.
/// @param message Message data to verify.
/// @param message_len Number of bytes in message.
/// @param signature Signature to verify.
/// @param signature_len Number of bytes in signature.
/// @return PqcProviderStatusOk for a valid signature, PqcProviderStatusVerificationFailed
///         for an invalid signature, or an error status.
pqc_provider_status pqc_provider_verify_public_key(pqc_provider_algorithm algorithm,
                                 const uint8_t* public_key,
                                 size_t public_key_len,
                                 const uint8_t* message,
                                 size_t message_len,
                                 const uint8_t* signature,
                                 size_t signature_len);

// ---------------------------------------------------------------------------
// KEM key management
// ---------------------------------------------------------------------------

/// @brief Generate a KEM key pair.
///
/// @param algorithm KEM algorithm to use.
/// @param key Output pointer receiving the generated key handle.
/// @return PqcProviderStatusOk on success, or an error status if generation fails.
pqc_provider_status pqc_provider_kem_keypair_generate(pqc_provider_algorithm algorithm, pqc_provider_key_handle** key);

/// @brief Export the public key associated with a KEM key handle.
///
/// @param key KEM key handle owned by the caller.
/// @param output Caller-provided output buffer for the public key.
/// @param output_len Input buffer capacity and output length written.
/// @return PqcProviderStatusOk on success, PqcProviderStatusBufferTooSmall when the
///         output buffer is insufficient, or another error status.
pqc_provider_status pqc_provider_kem_public_key_export(const pqc_provider_key_handle* key, uint8_t* output, size_t* output_len);

// ---------------------------------------------------------------------------
// KEM operations
// ---------------------------------------------------------------------------

/// @brief Encapsulate a shared secret using a public KEM key.
///
/// @param algorithm KEM algorithm to use.
/// @param public_key Public key used for encapsulation.
/// @param public_key_len Number of bytes in public_key.
/// @param ciphertext Caller-provided output buffer for the ciphertext.
/// @param ciphertext_len Input capacity and output ciphertext length.
/// @param shared_secret Caller-provided output buffer for the shared secret.
/// @param shared_secret_len Input capacity and output shared-secret length.
/// @return PqcProviderStatusOk on success, PqcProviderStatusBufferTooSmall when an
///         output buffer is insufficient, or another error status.
pqc_provider_status pqc_provider_kem_encapsulate(pqc_provider_algorithm algorithm,
                               const uint8_t* public_key,
                               size_t public_key_len,
                               uint8_t* ciphertext,
                               size_t* ciphertext_len,
                               uint8_t* shared_secret,
                               size_t* shared_secret_len);

/// @brief Decapsulate a shared secret using a private KEM key.
///
/// @param key KEM key handle owned by the caller.
/// @param ciphertext Ciphertext to decapsulate.
/// @param ciphertext_len Number of bytes in ciphertext.
/// @param shared_secret Caller-provided output buffer for the shared secret.
/// @param shared_secret_len Input capacity and output shared-secret length.
/// @return PqcProviderStatusOk on success, PqcProviderStatusBufferTooSmall when the
///         output buffer is insufficient, or another error status.
pqc_provider_status pqc_provider_kem_decapsulate(const pqc_provider_key_handle* key,
                               const uint8_t* ciphertext,
                               size_t ciphertext_len,
                               uint8_t* shared_secret,
                               size_t* shared_secret_len);

// ---------------------------------------------------------------------------
// Resource cleanup
// ---------------------------------------------------------------------------

/// @brief Destroy a key handle and release its backend resources.
///
/// The handle must not be used after this function returns.
///
/// @param key Key handle previously returned by a key-generation function.
void pqc_provider_key_destroy(pqc_provider_key_handle* key);

#ifdef __cplusplus
}
#endif

#endif  // SCORE_PQC_PROVIDER_FFI_H

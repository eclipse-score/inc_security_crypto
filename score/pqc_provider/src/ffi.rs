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

//! Rust side of the stable C ABI for the PQC Provider PQC backend.
//!
//! Cryptographic implementation types are intentionally not exposed to C++.
//! This module owns the opaque Rust key handle and translates failures to
//! stable `pqc_provider_status` values. The cryptographic entry points currently use
//! placeholder implementations and return `PqcProviderStatusUnsupportedAlgorithm`.

use core::ffi::c_void;

#[repr(C)]
/// Opaque key handle exposed through the C ABI.
///
/// The handle contents are private to Rust and must not be accessed by C++
/// callers.
pub struct pqc_provider_key_handle {
    _private: [u8; 0],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Status codes exchanged through the C ABI.
///
/// The numeric values must remain synchronized with `pqc_provider_ffi.h`.
pub enum pqc_provider_status {
    PqcProviderStatusOk = 0,                   // Operation completed successfully.
    PqcProviderStatusInvalidArgument = 1,      // One or more arguments are invalid.
    PqcProviderStatusBufferTooSmall = 2,       // An output buffer cannot hold the result.
    PqcProviderStatusUnsupportedAlgorithm = 3, // The requested algorithm is not supported.
    PqcProviderStatusVerificationFailed = 4,   // Verification completed and the signature is invalid.
    PqcProviderStatusCryptoFailure = 5,        // The backend failed during a cryptographic operation.
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Algorithms exchanged through the C ABI.
///
/// The numeric values must remain synchronized with `pqc_provider_ffi.h`.
pub enum pqc_provider_algorithm {
    PqcProviderAlgorithmMlDsa44 = 1,    // ML-DSA-44 signature algorithm.
    PqcProviderAlgorithmMlDsa65 = 2,    // ML-DSA-65 signature algorithm.
    PqcProviderAlgorithmMlDsa87 = 3,    // ML-DSA-87 signature algorithm.
    PqcProviderAlgorithmMlKem512 = 10,  // ML-KEM-512 key-encapsulation algorithm.
    PqcProviderAlgorithmMlKem768 = 11,  // ML-KEM-768 key-encapsulation algorithm.
    PqcProviderAlgorithmMlKem1024 = 12, // ML-KEM-1024 key-encapsulation algorithm.
}

/// Return the status used by the currently unimplemented backend operations.
fn unsupported() -> pqc_provider_status {
    pqc_provider_status::PqcProviderStatusUnsupportedAlgorithm
}

// The `extern "C"` ABI and `no_mangle` attribute preserve the C-compatible
// calling convention and exported symbol names declared in pqc_provider_ffi.h.

// ---------------------------------------------------------------------------
// Signature key management
// ---------------------------------------------------------------------------

/// Generate a signature key pair.
///
/// This entry point is currently a placeholder and returns
/// `PqcProviderStatusUnsupportedAlgorithm`.
#[no_mangle]
pub extern "C" fn pqc_provider_keypair_generate(
    _algorithm: pqc_provider_algorithm,
    _key: *mut *mut pqc_provider_key_handle,
) -> pqc_provider_status {
    unsupported()
}

/// Export a signature public key.
///
/// This entry point is currently a placeholder and returns
/// `PqcProviderStatusUnsupportedAlgorithm`.
#[no_mangle]
pub extern "C" fn pqc_provider_public_key_export(
    _key: *const pqc_provider_key_handle,
    _output: *mut u8,
    _output_len: *mut usize,
) -> pqc_provider_status {
    unsupported()
}

// ---------------------------------------------------------------------------
// KEM key management
// ---------------------------------------------------------------------------

/// Generate a KEM key pair.
///
/// This entry point is currently a placeholder and returns
/// `PqcProviderStatusUnsupportedAlgorithm`.
#[no_mangle]
pub extern "C" fn pqc_provider_kem_keypair_generate(
    _algorithm: pqc_provider_algorithm,
    _key: *mut *mut pqc_provider_key_handle,
) -> pqc_provider_status {
    unsupported()
}

/// Export a KEM public key.
///
/// This entry point is currently a placeholder and returns
/// `PqcProviderStatusUnsupportedAlgorithm`.
#[no_mangle]
pub extern "C" fn pqc_provider_kem_public_key_export(
    _key: *const pqc_provider_key_handle,
    _output: *mut u8,
    _output_len: *mut usize,
) -> pqc_provider_status {
    unsupported()
}

// ---------------------------------------------------------------------------
// Signature operations
// ---------------------------------------------------------------------------

/// Sign a message with a signature key.
///
/// This entry point is currently a placeholder and returns
/// `PqcProviderStatusUnsupportedAlgorithm`.
#[no_mangle]
pub extern "C" fn pqc_provider_sign(
    _key: *const pqc_provider_key_handle,
    _message: *const u8,
    _message_len: usize,
    _signature: *mut u8,
    _signature_len: *mut usize,
) -> pqc_provider_status {
    unsupported()
}

/// Verify a message signature.
///
/// This entry point is currently a placeholder and returns
/// `PqcProviderStatusUnsupportedAlgorithm`.
#[no_mangle]
pub extern "C" fn pqc_provider_verify(
    _key: *const pqc_provider_key_handle,
    _message: *const u8,
    _message_len: usize,
    _signature: *const u8,
    _signature_len: usize,
) -> pqc_provider_status {
    unsupported()
}

/// Verify a message signature using an imported public key.
///
/// This entry point is currently a placeholder and returns
/// `PqcProviderStatusUnsupportedAlgorithm`.
#[no_mangle]
pub extern "C" fn pqc_provider_verify_public_key(
    _algorithm: pqc_provider_algorithm,
    _public_key: *const u8,
    _public_key_len: usize,
    _message: *const u8,
    _message_len: usize,
    _signature: *const u8,
    _signature_len: usize,
) -> pqc_provider_status {
    unsupported()
}

// ---------------------------------------------------------------------------
// KEM operations
// ---------------------------------------------------------------------------

/// Encapsulate a shared secret using a public KEM key.
///
/// This entry point is currently a placeholder and returns
/// `PqcProviderStatusUnsupportedAlgorithm`.
#[no_mangle]
pub extern "C" fn pqc_provider_kem_encapsulate(
    _algorithm: pqc_provider_algorithm,
    _public_key: *const u8,
    _public_key_len: usize,
    _ciphertext: *mut u8,
    _ciphertext_len: *mut usize,
    _shared_secret: *mut u8,
    _shared_secret_len: *mut usize,
) -> pqc_provider_status {
    unsupported()
}

/// Decapsulate a shared secret using a private KEM key.
///
/// This entry point is currently a placeholder and returns
/// `PqcProviderStatusUnsupportedAlgorithm`.
#[no_mangle]
pub extern "C" fn pqc_provider_kem_decapsulate(
    _key: *const pqc_provider_key_handle,
    _ciphertext: *const u8,
    _ciphertext_len: usize,
    _shared_secret: *mut u8,
    _shared_secret_len: *mut usize,
) -> pqc_provider_status {
    unsupported()
}

// ---------------------------------------------------------------------------
// Resource cleanup
// ---------------------------------------------------------------------------

/// Destroy a key handle and release its backend resources.
#[no_mangle]
pub extern "C" fn pqc_provider_key_destroy(_key: *mut pqc_provider_key_handle) {}

/// Keep the opaque pointer type referenced without exposing its representation.
#[allow(dead_code)]
fn _opaque_pointer_marker(_: *const c_void) {}

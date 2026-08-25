// *******************************************************************************
// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// <https://www.apache.org/licenses/LICENSE-2.0>
//
// SPDX-License-Identifier: Apache-2.0
// *******************************************************************************

//! PKCS#11 v3.0 constants — CKR_*, CKM_*, CKO_*, CKK_*, CKA_*, CKF_*, CKS_*, CKU_*.

use super::types::*;

// ── CKR_* — Return codes ───────────────────────────────────────────────────
pub const CKR_OK: CK_RV = 0x00000000;
pub const CKR_CANCEL: CK_RV = 0x00000001;
pub const CKR_HOST_MEMORY: CK_RV = 0x00000002;
pub const CKR_SLOT_ID_INVALID: CK_RV = 0x00000003;
pub const CKR_GENERAL_ERROR: CK_RV = 0x00000005;
pub const CKR_FUNCTION_FAILED: CK_RV = 0x00000006;
pub const CKR_ARGUMENTS_BAD: CK_RV = 0x00000007;
pub const CKR_CANT_LOCK: CK_RV = 0x0000000A;
pub const CKR_NEED_TO_CREATE_THREADS: CK_RV = 0x00000009;
pub const CKR_ATTRIBUTE_READ_ONLY: CK_RV = 0x00000010;
pub const CKR_ATTRIBUTE_SENSITIVE: CK_RV = 0x00000011;
pub const CKR_ATTRIBUTE_TYPE_INVALID: CK_RV = 0x00000012;
pub const CKR_ATTRIBUTE_VALUE_INVALID: CK_RV = 0x00000013;
pub const CKR_DATA_INVALID: CK_RV = 0x00000020;
pub const CKR_DATA_LEN_RANGE: CK_RV = 0x00000021;
pub const CKR_DEVICE_ERROR: CK_RV = 0x00000030;
pub const CKR_DEVICE_MEMORY: CK_RV = 0x00000031;
pub const CKR_DEVICE_REMOVED: CK_RV = 0x00000032;
pub const CKR_ENCRYPTED_DATA_INVALID: CK_RV = 0x00000040;
pub const CKR_ENCRYPTED_DATA_LEN_RANGE: CK_RV = 0x00000041;
pub const CKR_FUNCTION_CANCELED: CK_RV = 0x00000050;
pub const CKR_FUNCTION_NOT_SUPPORTED: CK_RV = 0x00000054;
pub const CKR_STATE_UNSAVEABLE: CK_RV = 0x00000180;
pub const CKR_KEY_HANDLE_INVALID: CK_RV = 0x00000060;
pub const CKR_KEY_SIZE_RANGE: CK_RV = 0x00000062;
pub const CKR_KEY_TYPE_INCONSISTENT: CK_RV = 0x00000063;
pub const CKR_KEY_INDIGESTIBLE: CK_RV = 0x00000067;
pub const CKR_KEY_FUNCTION_NOT_PERMITTED: CK_RV = 0x00000068;
pub const CKR_KEY_NOT_WRAPPABLE: CK_RV = 0x00000069;
pub const CKR_KEY_UNEXTRACTABLE: CK_RV = 0x0000006A;
pub const CKR_UNWRAPPING_KEY_HANDLE_INVALID: CK_RV = 0x000000F0;
pub const CKR_WRAPPING_KEY_HANDLE_INVALID: CK_RV = 0x00000113;
pub const CKR_MECHANISM_INVALID: CK_RV = 0x00000070;
pub const CKR_MECHANISM_PARAM_INVALID: CK_RV = 0x00000071;
pub const CKR_OBJECT_HANDLE_INVALID: CK_RV = 0x00000082;
pub const CKR_OPERATION_ACTIVE: CK_RV = 0x00000090;
pub const CKR_OPERATION_NOT_INITIALIZED: CK_RV = 0x00000091;
pub const CKR_PIN_INCORRECT: CK_RV = 0x000000A0;
pub const CKR_PIN_LEN_RANGE: CK_RV = 0x000000A1;
pub const CKR_PIN_LOCKED: CK_RV = 0x000000A4;
pub const CKR_SESSION_CLOSED: CK_RV = 0x000000B0;
pub const CKR_SESSION_COUNT: CK_RV = 0x000000B1;
pub const CKR_SESSION_HANDLE_INVALID: CK_RV = 0x000000B3;
pub const CKR_SESSION_READ_ONLY: CK_RV = 0x000000B5;
pub const CKR_SIGNATURE_INVALID: CK_RV = 0x000000C0;
pub const CKR_SIGNATURE_LEN_RANGE: CK_RV = 0x000000C1;
pub const CKR_TEMPLATE_INCOMPLETE: CK_RV = 0x000000D0;
pub const CKR_TEMPLATE_INCONSISTENT: CK_RV = 0x000000D1;
pub const CKR_TOKEN_NOT_PRESENT: CK_RV = 0x000000E0;
pub const CKR_USER_ALREADY_LOGGED_IN: CK_RV = 0x00000100;
pub const CKR_USER_NOT_LOGGED_IN: CK_RV = 0x00000101;
pub const CKR_USER_PIN_NOT_INITIALIZED: CK_RV = 0x00000102;
pub const CKR_USER_TYPE_INVALID: CK_RV = 0x00000103;
pub const CKR_USER_ANOTHER_ALREADY_LOGGED_IN: CK_RV = 0x00000104;
pub const CKR_RANDOM_SEED_NOT_SUPPORTED: CK_RV = 0x00000120;
pub const CKR_RANDOM_NO_RNG: CK_RV = 0x00000121;
pub const CKR_BUFFER_TOO_SMALL: CK_RV = 0x00000150;
pub const CKR_CRYPTOKI_NOT_INITIALIZED: CK_RV = 0x00000190;
pub const CKR_TOKEN_NOT_RECOGNIZED: CK_RV = 0x000000e1;
pub const CKR_CRYPTOKI_ALREADY_INITIALIZED: CK_RV = 0x00000191;
pub const CKR_FUNCTION_REJECTED: CK_RV = 0x00000200;
pub const CKR_TOKEN_RESOURCE_EXCEEDED: CK_RV = 0x00000201;
pub const CKR_OPERATION_CANCEL_FAILED: CK_RV = 0x00000202;

// v3.0 additional return codes
pub const CKR_NEW_PIN_MODE: CK_RV = 0x000001B0;
pub const CKR_NEXT_OTP: CK_RV = 0x000001B1;
pub const CKR_EXCEEDED_MAX_ITERATIONS: CK_RV = 0x000001B5;
pub const CKR_FIPS_SELF_TEST_FAILED: CK_RV = 0x000001B6;
pub const CKR_LIBRARY_LOAD_FAILED: CK_RV = 0x000001B7;
pub const CKR_PIN_TOO_WEAK: CK_RV = 0x000001B8;
pub const CKR_PUBLIC_KEY_INVALID: CK_RV = 0x000001B9;
pub const CKR_AEAD_DECRYPT_FAILED: CK_RV = 0x00000035;

// ── CKM_* — Mechanism types ────────────────────────────────────────────────
pub const CKM_RSA_PKCS_KEY_PAIR_GEN: CK_MECHANISM_TYPE = 0x00000000;
pub const CKM_GENERIC_SECRET_KEY_GEN: CK_MECHANISM_TYPE = 0x00000350;
pub const CKM_RSA_PKCS: CK_MECHANISM_TYPE = 0x00000001;
pub const CKM_RSA_PKCS_OAEP: CK_MECHANISM_TYPE = 0x00000009;
pub const CKM_RSA_PKCS_PSS: CK_MECHANISM_TYPE = 0x0000000D;
pub const CKM_MD5_RSA_PKCS: CK_MECHANISM_TYPE = 0x00000005;
pub const CKM_SHA1_RSA_PKCS: CK_MECHANISM_TYPE = 0x00000006;
pub const CKM_SHA1_RSA_PKCS_PSS: CK_MECHANISM_TYPE = 0x0000000E;
pub const CKM_SHA256_RSA_PKCS: CK_MECHANISM_TYPE = 0x00000040;
pub const CKM_SHA256_RSA_PKCS_PSS: CK_MECHANISM_TYPE = 0x00000043;
pub const CKM_MD5: CK_MECHANISM_TYPE = 0x00000210;
pub const CKM_SHA_1: CK_MECHANISM_TYPE = 0x00000220;
pub const CKM_SHA256: CK_MECHANISM_TYPE = 0x00000250;
pub const CKM_SHA224: CK_MECHANISM_TYPE = 0x00000255;
pub const CKM_DES_KEY_GEN: CK_MECHANISM_TYPE = 0x00000120;
pub const CKM_DES_ECB: CK_MECHANISM_TYPE = 0x00000121;
pub const CKM_DES_CBC: CK_MECHANISM_TYPE = 0x00000122;
pub const CKM_DES3_KEY_GEN: CK_MECHANISM_TYPE = 0x00000131;
pub const CKM_DES3_ECB: CK_MECHANISM_TYPE = 0x00000132;
pub const CKM_DES3_CBC: CK_MECHANISM_TYPE = 0x00000133;
pub const CKM_EC_KEY_PAIR_GEN: CK_MECHANISM_TYPE = 0x00001040;
pub const CKM_ECDSA: CK_MECHANISM_TYPE = 0x00001041;
pub const CKM_ECDSA_SHA1: CK_MECHANISM_TYPE = 0x00001042;
pub const CKM_ECDSA_SHA256: CK_MECHANISM_TYPE = 0x00001043;
pub const CKM_AES_KEY_GEN: CK_MECHANISM_TYPE = 0x00001080;
pub const CKM_AES_CBC: CK_MECHANISM_TYPE = 0x00001082;
pub const CKM_AES_ECB: CK_MECHANISM_TYPE = 0x00001081;
pub const CKM_AES_CBC_PAD: CK_MECHANISM_TYPE = 0x00001085;
pub const CKM_AES_CTR: CK_MECHANISM_TYPE = 0x00001086;
pub const CKM_AES_GCM: CK_MECHANISM_TYPE = 0x00001087;
pub const CKM_AES_KEY_WRAP: CK_MECHANISM_TYPE = 0x00001090;
pub const CKM_ECDH1_DERIVE: CK_MECHANISM_TYPE = 0x00001050;

// v3.0 hash mechanisms
pub const CKM_SHA384: CK_MECHANISM_TYPE = 0x00000260;
pub const CKM_SHA512: CK_MECHANISM_TYPE = 0x00000270;
pub const CKM_SHA3_256: CK_MECHANISM_TYPE = 0x000002B0;
pub const CKM_SHA3_384: CK_MECHANISM_TYPE = 0x000002C0;
pub const CKM_SHA3_512: CK_MECHANISM_TYPE = 0x000002D0;

// HMAC mechanisms
pub const CKM_SHA_1_HMAC: CK_MECHANISM_TYPE = 0x00000221;
pub const CKM_SHA256_HMAC: CK_MECHANISM_TYPE = 0x00000251;
pub const CKM_SHA384_HMAC: CK_MECHANISM_TYPE = 0x00000261;
pub const CKM_SHA512_HMAC: CK_MECHANISM_TYPE = 0x00000271;

// v3.0 EdDSA mechanisms
pub const CKM_EC_EDWARDS_KEY_PAIR_GEN: CK_MECHANISM_TYPE = 0x00001055;
pub const CKM_EDDSA: CK_MECHANISM_TYPE = 0x00001057;

// v3.0 Montgomery key exchange
pub const CKM_EC_MONTGOMERY_KEY_PAIR_GEN: CK_MECHANISM_TYPE = 0x00001056;
pub const CKM_XEDDSA: CK_MECHANISM_TYPE = 0x00001058; // X25519/X448 signing

// v3.0 HKDF
pub const CKM_HKDF_DERIVE: CK_MECHANISM_TYPE = 0x0000402A;
pub const CKM_HKDF_DATA: CK_MECHANISM_TYPE = 0x0000402B;
pub const CKM_HKDF_KEY_GEN: CK_MECHANISM_TYPE = 0x0000402C;

// v3.0 ChaCha20-Poly1305
pub const CKM_CHACHA20_POLY1305: CK_MECHANISM_TYPE = 0x00004021;
pub const CKM_CHACHA20_KEY_GEN: CK_MECHANISM_TYPE = 0x00004022;
pub const CKM_CHACHA20: CK_MECHANISM_TYPE = 0x00004023;
pub const CKM_POLY1305_KEY_GEN: CK_MECHANISM_TYPE = 0x00004024;
pub const CKM_POLY1305: CK_MECHANISM_TYPE = 0x00004025;

// v3.0 additional RSA-PSS with SHA-384/512
pub const CKM_SHA384_RSA_PKCS: CK_MECHANISM_TYPE = 0x00000041;
pub const CKM_SHA512_RSA_PKCS: CK_MECHANISM_TYPE = 0x00000042;
pub const CKM_SHA384_RSA_PKCS_PSS: CK_MECHANISM_TYPE = 0x00000044;
pub const CKM_SHA512_RSA_PKCS_PSS: CK_MECHANISM_TYPE = 0x00000045;

// v3.0 ECDSA with SHA-384/512
pub const CKM_ECDSA_SHA384: CK_MECHANISM_TYPE = 0x00001044;
pub const CKM_ECDSA_SHA512: CK_MECHANISM_TYPE = 0x00001045;

// v3.0 SP 800-108 KDF
pub const CKM_SP800_108_COUNTER_KDF: CK_MECHANISM_TYPE = 0x000003AC;
pub const CKM_SP800_108_FEEDBACK_KDF: CK_MECHANISM_TYPE = 0x000003AD;

/// KDF type: raw shared secret, no derivation.
pub const CKD_NULL: CK_ULONG = 0x00000001;

// ── CKR_* — Legacy compat ─────────────────────────────────────────────
pub const CKR_FUNCTION_NOT_PARALLEL: CK_RV = 0x00000051;
pub const CKR_SESSION_PARALLEL_NOT_SUPPORTED: CK_RV = 0x000000B4;
pub const CKR_SESSION_EXISTS: CK_RV = 0x000000B6;
pub const CKR_SESSION_READ_ONLY_EXISTS: CK_RV = 0x000000B7;
pub const CKR_SESSION_READ_WRITE_SO_EXISTS: CK_RV = 0x000000B8;
pub const CKR_TOKEN_WRITE_PROTECTED: CK_RV = 0x000000E2;

// ── HKDF salt types (v3.0) ───────────────────────────────────────────
pub const CKF_HKDF_SALT_NULL: CK_ULONG = 0x00000001;
pub const CKF_HKDF_SALT_DATA: CK_ULONG = 0x00000002;
pub const CKF_HKDF_SALT_KEY: CK_ULONG = 0x00000004;

/// All mechanisms this token supports (used by C_GetMechanismList).
pub const SUPPORTED_MECHANISMS: &[CK_MECHANISM_TYPE] = &[
    // RSA
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_RSA_PKCS,
    CKM_RSA_PKCS_OAEP,
    CKM_SHA1_RSA_PKCS,     // legacy — filtered unless CRYPTOKI_LEGACY=1
    CKM_SHA1_RSA_PKCS_PSS, // legacy — filtered unless CRYPTOKI_LEGACY=1
    CKM_SHA256_RSA_PKCS,
    CKM_SHA256_RSA_PKCS_PSS,
    CKM_SHA384_RSA_PKCS,
    CKM_SHA512_RSA_PKCS,
    CKM_SHA384_RSA_PKCS_PSS,
    CKM_SHA512_RSA_PKCS_PSS,
    // EC (Weierstrass)
    CKM_EC_KEY_PAIR_GEN,
    CKM_ECDSA,
    CKM_ECDSA_SHA256,
    CKM_ECDSA_SHA384,
    CKM_ECDSA_SHA512,
    CKM_ECDH1_DERIVE,
    // EdDSA (v3.0)
    CKM_EC_EDWARDS_KEY_PAIR_GEN,
    CKM_EDDSA,
    // AES
    CKM_AES_KEY_GEN,
    CKM_AES_ECB,
    CKM_AES_CBC,
    CKM_AES_CBC_PAD,
    CKM_AES_CTR,
    CKM_AES_GCM,
    // Legacy DES/3DES key generation is needed for PKCS#11 v2.40 consumers.
    CKM_DES_KEY_GEN,
    CKM_DES3_KEY_GEN,
    CKM_DES_ECB,
    CKM_DES_CBC,
    CKM_DES3_ECB,
    CKM_DES3_CBC,
    // ChaCha20 (v3.0)
    CKM_CHACHA20_KEY_GEN,
    CKM_CHACHA20_POLY1305,
    // Hashing
    CKM_MD5,
    CKM_SHA_1,
    CKM_SHA256,
    CKM_SHA384,
    CKM_SHA512,
    CKM_SHA3_256,
    CKM_SHA3_384,
    CKM_SHA3_512,
    // HKDF (v3.0)
    CKM_HKDF_DERIVE,
    CKM_HKDF_KEY_GEN,
    // HMAC
    CKM_SHA_1_HMAC,
    CKM_SHA256_HMAC,
    CKM_SHA384_HMAC,
    CKM_SHA512_HMAC,
];

// ── CKO_* — Object classes ─────────────────────────────────────────────────
pub const CKO_DATA: CK_OBJECT_CLASS = 0x00000000;
pub const CKO_CERTIFICATE: CK_OBJECT_CLASS = 0x00000001;
pub const CKO_PUBLIC_KEY: CK_OBJECT_CLASS = 0x00000002;
pub const CKO_PRIVATE_KEY: CK_OBJECT_CLASS = 0x00000003;
pub const CKO_SECRET_KEY: CK_OBJECT_CLASS = 0x00000004;
pub const CKO_PROFILE: CK_OBJECT_CLASS = 0x00000009; // v3.0

// ── CKP_* — Profile IDs (v3.0) ──────────────────────────────────────────
pub const CKP_INVALID_ID: CK_ULONG = 0x00000000;
pub const CKP_BASELINE_PROVIDER: CK_ULONG = 0x00000001;
pub const CKP_EXTENDED_PROVIDER: CK_ULONG = 0x00000002;
pub const CKP_AUTHENTICATION_TOKEN: CK_ULONG = 0x00000003;
pub const CKP_PUBLIC_CERTIFICATES_TOKEN: CK_ULONG = 0x00000004;

// ── CKK_* — Key types ──────────────────────────────────────────────────────
pub const CKK_RSA: CK_KEY_TYPE = 0x00000000;
pub const CKK_DES: CK_KEY_TYPE = 0x00000013;
pub const CKK_DES3: CK_KEY_TYPE = 0x00000015;
pub const CKK_EC: CK_KEY_TYPE = 0x00000003;
pub const CKK_AES: CK_KEY_TYPE = 0x0000001F;
pub const CKK_GENERIC_SECRET: CK_KEY_TYPE = 0x00000010;
pub const CKK_CHACHA20: CK_KEY_TYPE = 0x00000033; // v3.0
pub const CKK_POLY1305: CK_KEY_TYPE = 0x00000034; // v3.0
pub const CKK_EC_EDWARDS: CK_KEY_TYPE = 0x00000040; // v3.0 — Ed25519, Ed448
pub const CKK_EC_MONTGOMERY: CK_KEY_TYPE = 0x00000041; // v3.0 — X25519, X448
pub const CKK_HKDF: CK_KEY_TYPE = 0x00000042; // v3.0

// ── CKA_* — Attribute types ────────────────────────────────────────────────
pub const CKA_CLASS: CK_ATTRIBUTE_TYPE = 0x00000000;
pub const CKA_TOKEN: CK_ATTRIBUTE_TYPE = 0x00000001;
pub const CKA_PRIVATE: CK_ATTRIBUTE_TYPE = 0x00000002;
pub const CKA_LABEL: CK_ATTRIBUTE_TYPE = 0x00000003;
pub const CKA_VALUE: CK_ATTRIBUTE_TYPE = 0x00000011;
pub const CKA_PRIVATE_EXPONENT: CK_ATTRIBUTE_TYPE = 0x00000123;
pub const CKA_PRIME_1: CK_ATTRIBUTE_TYPE = 0x00000124;
pub const CKA_PRIME_2: CK_ATTRIBUTE_TYPE = 0x00000125;
pub const CKA_EXPONENT_1: CK_ATTRIBUTE_TYPE = 0x00000126;
pub const CKA_EXPONENT_2: CK_ATTRIBUTE_TYPE = 0x00000127;
pub const CKA_COEFFICIENT: CK_ATTRIBUTE_TYPE = 0x00000128;
pub const CKA_KEY_TYPE: CK_ATTRIBUTE_TYPE = 0x00000100;
pub const CKA_ID: CK_ATTRIBUTE_TYPE = 0x00000102;
pub const CKA_SENSITIVE: CK_ATTRIBUTE_TYPE = 0x00000103;
pub const CKA_ENCRYPT: CK_ATTRIBUTE_TYPE = 0x00000104;
pub const CKA_DECRYPT: CK_ATTRIBUTE_TYPE = 0x00000105;
pub const CKA_TRUSTED: CK_ATTRIBUTE_TYPE = 0x00000086;
pub const CKA_WRAP: CK_ATTRIBUTE_TYPE = 0x00000106;
pub const CKA_UNWRAP: CK_ATTRIBUTE_TYPE = 0x00000107;
pub const CKA_SIGN: CK_ATTRIBUTE_TYPE = 0x00000108;
pub const CKA_VERIFY: CK_ATTRIBUTE_TYPE = 0x00000109;
pub const CKA_DERIVE: CK_ATTRIBUTE_TYPE = 0x0000010C;
pub const CKA_MODULUS: CK_ATTRIBUTE_TYPE = 0x00000120;
pub const CKA_MODULUS_BITS: CK_ATTRIBUTE_TYPE = 0x00000121;
pub const CKA_PUBLIC_EXPONENT: CK_ATTRIBUTE_TYPE = 0x00000122;
pub const CKA_VALUE_LEN: CK_ATTRIBUTE_TYPE = 0x00000161;
pub const CKA_EXTRACTABLE: CK_ATTRIBUTE_TYPE = 0x00000162;
pub const CKA_LOCAL: CK_ATTRIBUTE_TYPE = 0x00000163;
pub const CKA_NEVER_EXTRACTABLE: CK_ATTRIBUTE_TYPE = 0x00000164;
pub const CKA_ALWAYS_SENSITIVE: CK_ATTRIBUTE_TYPE = 0x00000165;
pub const CKA_KEY_GEN_MECHANISM: CK_ATTRIBUTE_TYPE = 0x00000166;
pub const CKA_ALWAYS_AUTHENTICATE: CK_ATTRIBUTE_TYPE = 0x00000202;
pub const CKA_WRAP_WITH_TRUSTED: CK_ATTRIBUTE_TYPE = 0x00000210;
pub const CKA_COPYABLE: CK_ATTRIBUTE_TYPE = 0x00000171; // v3.0
pub const CKA_DESTROYABLE: CK_ATTRIBUTE_TYPE = 0x00000172; // v3.0
pub const CKA_EC_PARAMS: CK_ATTRIBUTE_TYPE = 0x00000180;
pub const CKA_EC_POINT: CK_ATTRIBUTE_TYPE = 0x00000181;
pub const CKA_UNIQUE_ID: CK_ATTRIBUTE_TYPE = 0x0000010A; // v3.0
pub const CKA_PROFILE_ID: CK_ATTRIBUTE_TYPE = 0x00000601; // v3.0

// ── CKF_* — Flags ──────────────────────────────────────────────────────────

// Slot flags
pub const CKF_TOKEN_PRESENT: CK_FLAGS = 0x00000001;
pub const CKF_REMOVABLE_DEVICE: CK_FLAGS = 0x00000002;

// Token flags
pub const CKF_RNG: CK_FLAGS = 0x00000001;
pub const CKF_WRITE_PROTECTED: CK_FLAGS = 0x00000002;
pub const CKF_LOGIN_REQUIRED: CK_FLAGS = 0x00000004;
pub const CKF_USER_PIN_INITIALIZED: CK_FLAGS = 0x00000008;
pub const CKF_TOKEN_INITIALIZED: CK_FLAGS = 0x00000400;
pub const CKF_USER_PIN_COUNT_LOW: CK_FLAGS = 0x00010000;
pub const CKF_USER_PIN_FINAL_TRY: CK_FLAGS = 0x00020000;
pub const CKF_USER_PIN_LOCKED: CK_FLAGS = 0x00040000;
pub const CKF_SO_PIN_COUNT_LOW: CK_FLAGS = 0x01000000;
pub const CKF_SO_PIN_FINAL_TRY: CK_FLAGS = 0x02000000;
pub const CKF_SO_PIN_LOCKED: CK_FLAGS = 0x00400000;

// C_Initialize flags
pub const CKF_OS_LOCKING_OK: CK_FLAGS = 0x00000002;

// Session flags
pub const CKF_RW_SESSION: CK_FLAGS = 0x00000002;
pub const CKF_SERIAL_SESSION: CK_FLAGS = 0x00000004;

// Mechanism flags
pub const CKF_HW: CK_FLAGS = 0x00000001;
pub const CKF_ENCRYPT: CK_FLAGS = 0x00000100;
pub const CKF_DECRYPT: CK_FLAGS = 0x00000200;
pub const CKF_DIGEST: CK_FLAGS = 0x00000400;
pub const CKF_SIGN: CK_FLAGS = 0x00000800;
pub const CKF_VERIFY: CK_FLAGS = 0x00002000;
pub const CKF_GENERATE: CK_FLAGS = 0x00008000;
pub const CKF_GENERATE_KEY_PAIR: CK_FLAGS = 0x00010000;

// Mechanism flags (additional)
pub const CKF_WRAP: CK_FLAGS = 0x00020000;
pub const CKF_UNWRAP: CK_FLAGS = 0x00040000;
pub const CKF_DERIVE: CK_FLAGS = 0x00080000;

// ── CKS_* — Session states ─────────────────────────────────────────────────
pub const CKS_RO_PUBLIC_SESSION: CK_STATE = 0;
pub const CKS_RO_USER_FUNCTIONS: CK_STATE = 1;
pub const CKS_RW_PUBLIC_SESSION: CK_STATE = 2;
pub const CKS_RW_USER_FUNCTIONS: CK_STATE = 3;
pub const CKS_RW_SO_FUNCTIONS: CK_STATE = 4;

// ── CKU_* — User types ────────────────────────────────────────────────────
pub const CKU_SO: CK_USER_TYPE = 0;
pub const CKU_USER: CK_USER_TYPE = 1;
pub const CKU_CONTEXT_SPECIFIC: CK_USER_TYPE = 2; // v3.0

// ── CKF_* — Interface flags (v3.0) ──────────────────────────────────────
pub const CKF_INTERFACE_FORK_SAFE: CK_FLAGS = 0x00000001;

// ── Interface name (v3.0) ────────────────────────────────────────────────
/// The standard interface name for PKCS#11.
pub const PKCS11_INTERFACE_NAME: &[u8] = b"PKCS 11\0";

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    #[test]
    fn test_no_duplicate_constants() {
        // Read this very source file at compile time
        let source = include_str!("constants.rs");

        // Domain Prefix -> (Value -> Variable Name)
        let mut domains: HashMap<&str, HashMap<String, String>> = HashMap::new();

        for line in source.lines() {
            let line = line.trim();
            if !line.starts_with("pub const ") {
                continue;
            }

            let parts: Vec<&str> = line.splitn(2, '=').collect();
            if parts.len() != 2 {
                continue;
            }

            let decl = parts[0].trim();
            let val_str = parts[1].split_whitespace().next().unwrap_or("").trim_end_matches(';');

            let decl_parts: Vec<&str> = decl.split(':').collect();
            if decl_parts.len() != 2 {
                continue;
            }

            let name = decl_parts[0].replace("pub const ", "").trim().to_string();

            // Group by domains that must be strictly unique.
            // (We skip flags like CKF_ or CKS_ because bitmasks naturally share values across different structs)
            let prefix = if name.starts_with("CKR_") {
                "CKR_"
            } else if name.starts_with("CKA_") {
                "CKA_"
            } else if name.starts_with("CKM_") {
                "CKM_"
            } else if name.starts_with("CKO_") {
                "CKO_"
            } else if name.starts_with("CKK_") {
                "CKK_"
            } else {
                continue;
            };

            let domain = domains.entry(prefix).or_default();
            if let Some(existing) = domain.get(val_str) {
                panic!(
                    "Collision detected! Both `{}` and `{}` share the value `{}` in the {} domain.",
                    existing, name, val_str, prefix
                );
            }
            domain.insert(val_str.to_string(), name);
        }
    }

    #[test]
    fn test_cpp_header_sync() {
        let rs_source = include_str!("constants.rs");
        let cpp_source = include_str!("../cpp/pkcs11.h");

        let mut rs_constants = HashMap::new();
        for line in rs_source.lines() {
            let line = line.trim();
            if line.starts_with("pub const ") {
                let parts: Vec<&str> = line.splitn(2, '=').collect();
                if parts.len() == 2 {
                    let decl = parts[0].trim();
                    let val_str = parts[1].split_whitespace().next().unwrap_or("").trim_end_matches(';');
                    let decl_parts: Vec<&str> = decl.split(':').collect();
                    if decl_parts.len() == 2 {
                        let name = decl_parts[0].replace("pub const ", "").trim().to_string();
                        rs_constants.insert(name, val_str.to_string());
                    }
                }
            }
        }

        // Verify every CKR, CKM, CKA, CKK, CKO, CKU in the C++ header matches the Rust constants
        for line in cpp_source.lines() {
            let line = line.trim();
            if line.starts_with("#define ") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let name = parts[1].to_string();
                    if name.starts_with("CKR_")
                        || name.starts_with("CKM_")
                        || name.starts_with("CKA_")
                        || name.starts_with("CKK_")
                        || name.starts_with("CKO_")
                        || name.starts_with("CKU_")
                    {
                        let cpp_val = parts[2].trim_end_matches("UL");
                        if let Some(rs_val) = rs_constants.get(&name) {
                            assert_eq!(
                                cpp_val.to_lowercase(),
                                rs_val.to_lowercase(),
                                "Constant mismatch for {}! C++ has {}, Rust has {}",
                                name,
                                cpp_val,
                                rs_val
                            );
                        } else {
                            panic!(
                                "Constant {} is defined in C++ header but missing in Rust constants.rs",
                                name
                            );
                        }
                    }
                }
            }
        }
    }
}

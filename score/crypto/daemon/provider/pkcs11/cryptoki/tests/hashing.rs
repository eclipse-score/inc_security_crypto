// *******************************************************************************
// Copyright (c) 2025 Contributors to the Eclipse Foundation
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

//!
//! Each test follows:
//!   loadHSMLibrary → connectToSlot (Initialize + OpenSession + Login)
//!   → generateHash (C_DigestInit → C_Digest or C_DigestUpdate × N → C_DigestFinal)
//!   → disconnectFromSlot (Logout + CloseSession + Finalize)

use cryptoki::pkcs11::constants::*;
use cryptoki::pkcs11::types::*;
use cryptoki::pkcs11::{
    C_Initialize,
    C_OpenSession, C_CloseSession,
    C_Login, C_Logout,
    C_DigestInit, C_Digest, C_DigestUpdate, C_DigestFinal,
};
use std::ptr;
use std::sync::Once;

const SLOT_PIN: &[u8] = b"1234";

static INIT: Once = Once::new();

fn init() {
    INIT.call_once(|| unsafe {
        let rv = C_Initialize(ptr::null_mut());
        assert!(
            rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED,
            "C_Initialize failed: {rv:#010x}",
        );
    });
}

// ── Shared helpers ────────────────────────────────────────────────────────

unsafe fn connect_to_slot() -> CK_SESSION_HANDLE {
    let mut h: CK_SESSION_HANDLE = 0;
    assert_eq!(
        C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, ptr::null_mut(), None, &mut h),
        CKR_OK,
    );
    let rv = C_Login(h, CKU_USER, SLOT_PIN.as_ptr(), SLOT_PIN.len() as CK_ULONG);
    assert!(rv == CKR_OK || rv == CKR_USER_ALREADY_LOGGED_IN, "C_Login failed: {rv:#x}");
    h
}

unsafe fn disconnect_from_slot(h: CK_SESSION_HANDLE) {
    let rv = C_Logout(h);
    assert!(rv == CKR_OK || rv == CKR_USER_NOT_LOGGED_IN, "C_Logout failed: {rv:#x}");
    assert_eq!(C_CloseSession(h), CKR_OK);
}

// ═════════════════════════════════════════════════════════════════════════════
// CKM_SHA256
// ═════════════════════════════════════════════════════════════════════════════

/// sequence:
///   loadHSMLibrary() → connectToSlot() → generateHash() → disconnectFromSlot()
///
/// generateHash():
///   C_DigestInit(CKM_SHA256) → C_Digest(data, NULL, &digestLen) → C_Digest(data, digest, &digestLen)
///
/// The uses a two-call pattern: first pass NULL to get length, then allocate and call again.
/// We verify against the known SHA-256("abc") vector.
#[test]
fn ckm_sha256() {
    init();
    unsafe {
        // Step 1: Initialize (shared)
        // Step 2: Open session + login
        let h_session = connect_to_slot();

        // plainData (CK_BYTE plainData[] = "Earth is the third planet of our Solar System.")
        let plain_data = b"Earth is the third planet of our Solar System.";

        // Step 3: Initialize digest operation with CKM_SHA256
        // (CK_MECHANISM mech = {CKM_SHA256}; C_DigestInit(hSession, &mech))
        let mech = CK_MECHANISM {
            mechanism: CKM_SHA256,
            pParameter: ptr::null(),
            ulParameterLen: 0,
        };
        assert_eq!(C_DigestInit(h_session, &mech), CKR_OK);

        // Step 4: First C_Digest call with NULL output buffer to query output length
        // (C_Digest(hSession, plainData, sizeof(plainData)-1, NULL, &digestLen))
        let mut digest_len: CK_ULONG = 0;
        assert_eq!(
            C_Digest(h_session, plain_data.as_ptr(), plain_data.len() as CK_ULONG, ptr::null_mut(), &mut digest_len),
            CKR_OK,
        );
        assert_eq!(digest_len, 32, "SHA-256 output must be 32 bytes");

        // Step 5: Second C_Digest call with allocated buffer to retrieve hash
        // (digest = new CK_BYTE[digestLen]; C_Digest(hSession, plainData, ..., digest, &digestLen))
        let mut digest = vec![0u8; 32];
        let mut digest_len2: CK_ULONG = 32;
        assert_eq!(
            C_Digest(h_session, plain_data.as_ptr(), plain_data.len() as CK_ULONG, digest.as_mut_ptr(), &mut digest_len2),
            CKR_OK,
        );
        assert_ne!(digest, [0u8; 32], "hash output must not be all zeros");

        // Step 6: Verify known SHA-256("abc") test vector
        // SHA-256("abc") = ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad
        assert_eq!(C_DigestInit(h_session, &mech), CKR_OK);
        let abc = b"abc";
        let mut abc_hash = vec![0u8; 32];
        let mut abc_len: CK_ULONG = 32;
        assert_eq!(C_Digest(h_session, abc.as_ptr(), 3, abc_hash.as_mut_ptr(), &mut abc_len), CKR_OK);
        let expected_sha256_abc = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(abc_hash, expected_sha256_abc, "SHA-256('abc') vector mismatch");

        // Step 7: Logout and close session
        disconnect_from_slot(h_session);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// CKM_SHA_1
// ═════════════════════════════════════════════════════════════════════════════

/// sequence:
///   loadHSMLibrary() → connectToSlot() → generateHash() → disconnectFromSlot()
///
/// generateHash():
///   CK_MECHANISM mech = {CKM_SHA_1}
///   C_DigestInit → C_Digest(NULL, &digestLen) → C_Digest(digest, &digestLen)
///
/// We verify against the known SHA-1("abc") vector.
#[test]
fn ckm_sha1() {
    init();
    unsafe {
        // Step 1: Initialize (shared)
        // Step 2: Open session + login
        let h_session = connect_to_slot();

        // plainData (CK_BYTE plainData[] = "Earth is the third planet of our Solar System.")
        let plain_data = b"Earth is the third planet of our Solar System.";

        // Step 3: Initialize SHA-1 digest operation
        // (CK_MECHANISM mech = {CKM_SHA_1}; C_DigestInit(hSession, &mech))
        let mech = CK_MECHANISM {
            mechanism: CKM_SHA_1,
            pParameter: ptr::null(),
            ulParameterLen: 0,
        };
        assert_eq!(C_DigestInit(h_session, &mech), CKR_OK);

        // Step 4: Query output length (NULL buffer)
        // (C_Digest(hSession, plainData, sizeof(plainData)-1, NULL, &digestLen))
        let mut digest_len: CK_ULONG = 0;
        assert_eq!(
            C_Digest(h_session, plain_data.as_ptr(), plain_data.len() as CK_ULONG, ptr::null_mut(), &mut digest_len),
            CKR_OK,
        );
        assert_eq!(digest_len, 20, "SHA-1 output must be 20 bytes");

        // Step 5: Compute hash and retrieve it
        // (digest = new CK_BYTE[digestLen]; C_Digest(hSession, plainData, ..., digest, &digestLen))
        let mut digest = vec![0u8; 20];
        let mut digest_len2: CK_ULONG = 20;
        assert_eq!(
            C_Digest(h_session, plain_data.as_ptr(), plain_data.len() as CK_ULONG, digest.as_mut_ptr(), &mut digest_len2),
            CKR_OK,
        );
        assert_ne!(digest, [0u8; 20], "hash output must not be all zeros");

        // Step 6: Verify known SHA-1("abc") test vector
        // SHA-1("abc") = a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d
        assert_eq!(C_DigestInit(h_session, &mech), CKR_OK);
        let mut abc_hash = vec![0u8; 20];
        let mut abc_len: CK_ULONG = 20;
        assert_eq!(C_Digest(h_session, b"abc".as_ptr(), 3, abc_hash.as_mut_ptr(), &mut abc_len), CKR_OK);
        let expected_sha1_abc = [
            0xa9u8, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
            0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
            0x9c, 0xd0, 0xd8, 0x9d,
        ];
        assert_eq!(abc_hash, expected_sha1_abc, "SHA-1('abc') vector mismatch");

        // Step 7: Logout and close session
        disconnect_from_slot(h_session);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// CKM_MD5
// ═════════════════════════════════════════════════════════════════════════════

/// sequence:
///   loadHSMLibrary() → connectToSlot() → generateHash() → disconnectFromSlot()
///
/// generateHash():
///   CK_MECHANISM mech = {CKM_MD5}
///   C_DigestInit → C_Digest(NULL, &digestLen) → C_Digest(digest, &digestLen)
///
/// We verify against known MD5 test vectors for empty string and "abc".
#[test]
fn ckm_md5() {
    init();
    unsafe {
        // Step 1: Initialize (shared)
        // Step 2: Open session + login
        let h_session = connect_to_slot();

        // Step 3: Initialize MD5 digest operation
        // (CK_MECHANISM mech = {CKM_MD5}; C_DigestInit(hSession, &mech))
        let mech = CK_MECHANISM {
            mechanism: CKM_MD5,
            pParameter: ptr::null(),
            ulParameterLen: 0,
        };
        assert_eq!(C_DigestInit(h_session, &mech), CKR_OK);

        // Step 4: Query output length
        let mut digest_len: CK_ULONG = 0;
        assert_eq!(C_Digest(h_session, b"".as_ptr(), 0, ptr::null_mut(), &mut digest_len), CKR_OK);
        assert_eq!(digest_len, 16, "MD5 output must be 16 bytes");

        // Step 5: Known MD5("") = d41d8cd9 8f00b204 e9800998 ecf8427e
        // (digest = new CK_BYTE[digestLen]; C_Digest(..., digest, &digestLen))
        let mut digest_empty = vec![0u8; 16];
        let mut len1: CK_ULONG = 16;
        assert_eq!(C_Digest(h_session, b"".as_ptr(), 0, digest_empty.as_mut_ptr(), &mut len1), CKR_OK);
        let expected_md5_empty = [
            0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
            0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e,
        ];
        assert_eq!(digest_empty, expected_md5_empty, "MD5('') vector mismatch");

        // Step 6: Known MD5("abc") = 90015098 3cd24fb0 d6963f7d 28e17f72
        assert_eq!(C_DigestInit(h_session, &mech), CKR_OK);
        let mut digest_abc = vec![0u8; 16];
        let mut len2: CK_ULONG = 16;
        assert_eq!(C_Digest(h_session, b"abc".as_ptr(), 3, digest_abc.as_mut_ptr(), &mut len2), CKR_OK);
        let expected_md5_abc = [
            0x90u8, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
            0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72,
        ];
        assert_eq!(digest_abc, expected_md5_abc, "MD5('abc') vector mismatch");

        // Step 7: Logout and close session
        disconnect_from_slot(h_session);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// multi_part_digest
// ═════════════════════════════════════════════════════════════════════════════

/// sequence:
///   loadHSMLibrary() → connectToSlot() → hash_of_a_file() → disconnectFromSlot()
///
/// hash_of_a_file():
///   C_DigestInit(CKM_SHA256) →
///   [loop] C_DigestUpdate(hSession, buffer, bufferLen) for each chunk →
///   C_DigestFinal(hSession, NULL, &digestLen) →
///   C_DigestFinal(hSession, digest, &digestLen)
///
/// We simulate chunked file reads using in-memory byte slices, then compare
/// against the one-shot result to confirm equivalence.
#[test]
fn multi_part_digest_sha256() {
    init();
    unsafe {
        // Step 1: Initialize (shared)
        // Step 2: Open session + login
        let h_session = connect_to_slot();

        // Simulated file chunks (reads file in 32-byte buffers via ifstream)
        let chunk1 = b"Earth is the third ";
        let chunk2 = b"planet of our ";
        let chunk3 = b"Solar System.";
        let full   = b"Earth is the third planet of our Solar System.";

        let mech = CK_MECHANISM {
            mechanism: CKM_SHA256,
            pParameter: ptr::null(),
            ulParameterLen: 0,
        };

        // Step 3: Initialize the streaming digest
        // (C_DigestInit(hSession, &mech))
        assert_eq!(C_DigestInit(h_session, &mech), CKR_OK);

        // Step 4: Feed chunks via C_DigestUpdate
        // ([loop] C_DigestUpdate(hSession, buffer, bufferLen))
        assert_eq!(C_DigestUpdate(h_session, chunk1.as_ptr(), chunk1.len() as CK_ULONG), CKR_OK);
        assert_eq!(C_DigestUpdate(h_session, chunk2.as_ptr(), chunk2.len() as CK_ULONG), CKR_OK);
        assert_eq!(C_DigestUpdate(h_session, chunk3.as_ptr(), chunk3.len() as CK_ULONG), CKR_OK);

        // Step 5: Finalize — first call with NULL to get output length
        // (C_DigestFinal(hSession, NULL, &digestLen))
        let mut digest_len: CK_ULONG = 0;
        assert_eq!(C_DigestFinal(h_session, ptr::null_mut(), &mut digest_len), CKR_OK);
        assert_eq!(digest_len, 32);

        // Step 6: Second call retrieves hash (C_DigestFinal with NULL does NOT consume the context)
        // (digest = new CK_BYTE[digestLen]; C_DigestFinal(hSession, digest, &digestLen))
        let mut multi_digest = vec![0u8; 32];
        let mut multi_len: CK_ULONG = 32;
        assert_eq!(C_DigestFinal(h_session, multi_digest.as_mut_ptr(), &mut multi_len), CKR_OK);

        // Step 7: One-shot reference digest of the same full data
        assert_eq!(C_DigestInit(h_session, &mech), CKR_OK);
        let mut one_digest = vec![0u8; 32];
        let mut one_len: CK_ULONG = 32;
        assert_eq!(
            C_Digest(h_session, full.as_ptr(), full.len() as CK_ULONG, one_digest.as_mut_ptr(), &mut one_len),
            CKR_OK,
        );

        // Multi-part result must match the one-shot result
        assert_eq!(multi_digest, one_digest, "multi-part digest must equal one-shot digest");

        // Step 8: Logout and close session
        disconnect_from_slot(h_session);
    }
}

/// Extension: multi-part SHA-1 digest
#[test]
fn multi_part_digest_sha1() {
    init();
    unsafe {
        // Step 1: Initialize (shared)
        // Step 2: Open session + login
        let h_session = connect_to_slot();

        let mech = CK_MECHANISM {
            mechanism: CKM_SHA_1,
            pParameter: ptr::null(),
            ulParameterLen: 0,
        };

        // Step 3: Initialize streaming SHA-1 digest
        assert_eq!(C_DigestInit(h_session, &mech), CKR_OK);

        // Step 4: Feed two chunks "ab" + "c" = "abc"
        assert_eq!(C_DigestUpdate(h_session, b"ab".as_ptr(), 2), CKR_OK);
        assert_eq!(C_DigestUpdate(h_session, b"c".as_ptr(), 1), CKR_OK);

        // Step 5: Finalize and retrieve digest
        let mut digest = vec![0u8; 20];
        let mut len: CK_ULONG = 20;
        assert_eq!(C_DigestFinal(h_session, digest.as_mut_ptr(), &mut len), CKR_OK);

        // SHA-1("abc") = a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d
        let expected = [
            0xa9u8, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
            0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
            0x9c, 0xd0, 0xd8, 0x9d,
        ];
        assert_eq!(digest, expected, "multi-part SHA-1('abc') vector mismatch");

        // Step 6: Logout and close session
        disconnect_from_slot(h_session);
    }
}

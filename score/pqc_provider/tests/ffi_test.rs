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

use pqc_provider::{
    pqc_provider_algorithm, pqc_provider_key_destroy, pqc_provider_keypair_generate, pqc_provider_kem_decapsulate,
    pqc_provider_kem_encapsulate, pqc_provider_kem_keypair_generate, pqc_provider_kem_public_key_export,
    pqc_provider_public_key_export, pqc_provider_sign, pqc_provider_status, pqc_provider_verify, pqc_provider_verify_public_key,
    pqc_provider_key_handle,
};

#[test]
fn exported_operations_report_unsupported_until_backend_is_connected() {
    // These are minimal placeholder values for the current stub operations:
    // key remains null, length is a dummy size parameter, and byte provides a
    // minimal message or data reference.
    let mut key: *mut pqc_provider_key_handle = core::ptr::null_mut();
    let mut length = 0usize;
    let byte = 0u8;

    // Signature key management must return the stable unsupported status while
    // the concrete implementation is not integrated.
    assert_eq!(
        pqc_provider_keypair_generate(pqc_provider_algorithm::PqcProviderAlgorithmMlDsa44, &mut key),
        pqc_provider_status::PqcProviderStatusUnsupportedAlgorithm
    );

    assert_eq!(
        pqc_provider_public_key_export(key, core::ptr::null_mut(), &mut length),
        pqc_provider_status::PqcProviderStatusUnsupportedAlgorithm
    );

    // KEM key management follows the same stub contract.
    assert_eq!(
        pqc_provider_kem_keypair_generate(pqc_provider_algorithm::PqcProviderAlgorithmMlKem512, &mut key),
        pqc_provider_status::PqcProviderStatusUnsupportedAlgorithm
    );
    assert_eq!(
        pqc_provider_kem_public_key_export(key, core::ptr::null_mut(), &mut length),
        pqc_provider_status::PqcProviderStatusUnsupportedAlgorithm
    );

    // Signature operations use the same unsupported status until implemented.
    assert_eq!(
        pqc_provider_sign(key, &byte, 0, core::ptr::null_mut(), &mut length),
        pqc_provider_status::PqcProviderStatusUnsupportedAlgorithm
    );
    assert_eq!(
        pqc_provider_verify(key, &byte, 0, &byte, 0),
        pqc_provider_status::PqcProviderStatusUnsupportedAlgorithm
    );
    assert_eq!(
        pqc_provider_verify_public_key(
            pqc_provider_algorithm::PqcProviderAlgorithmMlDsa44,
            &byte,
            0,
            &byte,
            0,
            &byte,
            0,
        ),
        pqc_provider_status::PqcProviderStatusUnsupportedAlgorithm
    );

    // KEM operations also remain unsupported in the current backend stub.
    assert_eq!(
        pqc_provider_kem_encapsulate(
            pqc_provider_algorithm::PqcProviderAlgorithmMlKem512,
            &byte,
            0,
            core::ptr::null_mut(),
            &mut length,
            core::ptr::null_mut(),
            &mut length,
        ),
        pqc_provider_status::PqcProviderStatusUnsupportedAlgorithm
    );
    assert_eq!(
        pqc_provider_kem_decapsulate(key, &byte, 0, core::ptr::null_mut(), &mut length),
        pqc_provider_status::PqcProviderStatusUnsupportedAlgorithm
    );

    // Resource cleanup is intentionally a no-op for the current null/stub handle.
    pqc_provider_key_destroy(key);
}

#[test]
fn ffi_status_and_algorithm_values_are_stable() {
    // Status values are part of the stable C ABI.
    assert_eq!(pqc_provider_status::PqcProviderStatusOk as u32, 0);
    assert_eq!(pqc_provider_status::PqcProviderStatusInvalidArgument as u32, 1);
    assert_eq!(pqc_provider_status::PqcProviderStatusBufferTooSmall as u32, 2);
    assert_eq!(pqc_provider_status::PqcProviderStatusUnsupportedAlgorithm as u32, 3);
    assert_eq!(pqc_provider_status::PqcProviderStatusVerificationFailed as u32, 4);
    assert_eq!(pqc_provider_status::PqcProviderStatusCryptoFailure as u32, 5);

    // Algorithm values must match the #[repr(C)] declarations in the C header.
    assert_eq!(pqc_provider_algorithm::PqcProviderAlgorithmMlDsa44 as u32, 1);
    assert_eq!(pqc_provider_algorithm::PqcProviderAlgorithmMlDsa65 as u32, 2);
    assert_eq!(pqc_provider_algorithm::PqcProviderAlgorithmMlDsa87 as u32, 3);
    assert_eq!(pqc_provider_algorithm::PqcProviderAlgorithmMlKem512 as u32, 10);
    assert_eq!(pqc_provider_algorithm::PqcProviderAlgorithmMlKem768 as u32, 11);
    assert_eq!(pqc_provider_algorithm::PqcProviderAlgorithmMlKem1024 as u32, 12);
}

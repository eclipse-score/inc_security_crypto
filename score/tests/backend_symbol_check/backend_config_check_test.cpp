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

// Compile-time and run-time checks that the crypto daemon backend configuration
// in backend_exports.bzl is reflected correctly in the preprocessor defines
// that gate backend code paths.
//
// If you change ENABLE_PKCS11_BACKEND or ENABLE_SCORE_BACKEND in
// backend_exports.bzl, update the expected values below accordingly.

#include <gtest/gtest.h>

// ── Expected configuration ───────────────────────────────────────────────────
// Mirrors backend_exports.bzl:
//   ENABLE_PKCS11_BACKEND = True   → SCORE_CRYPTO_PKCS11_ENABLED defined
//   ENABLE_SCORE_BACKEND  = False  → SCORE_BACKEND_ENABLED not defined

TEST(BackendConfig, Pkcs11BackendIsEnabled)
{
#ifdef SCORE_CRYPTO_PKCS11_ENABLED
    SUCCEED();
#else
    FAIL() << "SCORE_CRYPTO_PKCS11_ENABLED is not defined — "
              "ENABLE_PKCS11_BACKEND should be True in backend_exports.bzl";
#endif
}

TEST(BackendConfig, ScoreBackendIsEnabled)
{
#ifdef SCORE_BACKEND_ENABLED
    SUCCEED();
#else
    FAIL() << "SCORE_BACKEND_ENABLED is not defined — "
              "ENABLE_SCORE_BACKEND should be True in backend_exports.bzl";
#endif
}

TEST(BackendConfig, OpenSslBackendIsEnabled)
{
#ifdef SCORE_BACKEND_OPENSSL_ENABLED
    SUCCEED();
#else
    FAIL() << "SCORE_BACKEND_OPENSSL_ENABLED is not defined — "
              "OpenSSL backend should be active when ENABLE_SCORE_BACKEND is True";
#endif
}

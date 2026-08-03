# *******************************************************************************
# Copyright (c) 2026 Contributors to the Eclipse Foundation
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
# *******************************************************************************

load("@rules_cc//cc:defs.bzl", "cc_test")

# Verifies that the preprocessor defines emitted by the backend targets reflect
# the active bool_flag configuration:
#
#   (default)                                                              → SCORE_CRYPTO_PKCS11_ENABLED defined
#   --//score/crypto/src/backend:score_crypto_pkcs11_enabled=False        → SCORE_CRYPTO_PKCS11_ENABLED NOT defined
#   (default)                                                              → SCORE_BACKEND_ENABLED defined
#   --//score/crypto/src/backend:score_crypto_score_backend_enabled=False → SCORE_BACKEND_ENABLED NOT defined
#
# Checks happen at compile time (wrong config → build failure) and are confirmed
# at runtime via gtest assertions.
#
# Run with:
#   bazel test //score/tests/backend_symbol_check:backend_config_check
#   bazel test //score/tests/backend_symbol_check:backend_config_check \
#       --//score/crypto/src/backend:score_crypto_pkcs11_enabled=False
cc_test(
    name = "backend_config_check",
    srcs = ["backend_config_check_test.cpp"],
    deps = [
        "//score/crypto/src/backend:pkcs11_backend_defines",
        "//score/crypto/src/backend:score_backend_defines",
        "//score/crypto/src/backend/score_provider/openssl:openssl_backend_define",
        "@googletest//:gtest_main",
    ],
)

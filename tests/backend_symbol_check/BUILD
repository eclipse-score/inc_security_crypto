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

# Verifies that the preprocessor defines emitted by the backend_defines targets
# match the configuration declared in backend_exports.bzl:
#
#   ENABLE_PKCS11_BACKEND = True   → SCORE_CRYPTO_PKCS11_ENABLED is defined
#   ENABLE_SCORE_BACKEND  = False  → SCORE_BACKEND_ENABLED is NOT defined
#
# Checks happen at compile time (wrong config → build failure) and are confirmed
# at runtime via gtest assertions.
#
# If you change ENABLE_PKCS11_BACKEND or ENABLE_SCORE_BACKEND in
# backend_exports.bzl, update the expected values in backend_config_check_test.cpp.
#
# Run with:
#   bazel test //tests/backend_symbol_check:backend_config_check
cc_test(
    name = "backend_config_check",
    srcs = ["backend_config_check_test.cpp"],
    deps = [
        "//score/crypto/backend:pkcs11_backend_defines",
        "//score/crypto/backend/score_provider:score_backend_defines",
        "@googletest//:gtest_main",
    ],
)

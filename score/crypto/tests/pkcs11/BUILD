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

load("@rules_cc//cc:defs.bzl", "cc_library")

# Lightweight environment setup helper
cc_library(
    name = "pkcs11_test_env_setup",
    testonly = True,
    hdrs = ["pkcs11_test_env_setup.hpp"],
    includes = ["."],
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/tests/utility",
        "@googletest//:gtest",
    ],
)

# Vendor-neutral PKCS#11 test fixture supporting interchangeable backends
# (SoftHSM2, Rust Cryptoki, or dynamic loader) via active_pkcs11_backend.
cc_library(
    name = "pkcs11_test_fixture",
    testonly = True,
    hdrs = ["pkcs11_test_fixture.hpp"],
    includes = ["."],
    visibility = ["//:__subpackages__"],
    deps = [
        ":pkcs11_test_env_setup",
        "//score/crypto/src/backend:active_pkcs11_backend",
        "@googletest//:gtest",
    ],
)

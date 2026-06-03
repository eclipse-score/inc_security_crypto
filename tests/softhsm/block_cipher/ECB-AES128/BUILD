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

cc_test(
    name = "test_softhsm_ecb_aes128",
    srcs = ["test_softhsm_ecb_aes128.cpp"],
    data = [
        "//tests/test_vectors/block_cipher/ECB-AES128:block_cipher_test_vectors",
    ],
    linkstatic = True,
    deps = [
        "//tests/utility",
        "//third_party/soft_hsm:libsofthsm_shared",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

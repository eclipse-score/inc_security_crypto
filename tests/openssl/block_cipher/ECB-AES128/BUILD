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

# Bazel build file for AES-128-ECB block cipher tests

load("@rules_cc//cc:cc_test.bzl", "cc_test")

cc_test(
    name = "test_ecb_aes128",
    timeout = "short",
    srcs = ["test_ecb_aes128.cpp"],
    data = [
        "//tests/test_vectors/block_cipher/ECB-AES128:block_cipher_test_vectors",
    ],
    dynamic_deps = [
        "//third_party/openssl:openssl_shared",
    ],
    deps = [
        "//tests/utility",
        "//third_party/openssl",
        "@googletest//:gtest",
    ],
)

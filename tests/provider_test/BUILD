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
    name = "test_provider",
    srcs = ["test_provider.cpp"],
    data = ["//tests/test_vectors/hash:hash_test_vectors"],
    deps = [
        "//score/crypto/daemon/common",
        "//score/crypto/daemon/data_manager",
        "//score/crypto/daemon/provider/handler:crypto_handler_factory_headers",
        "//score/crypto/daemon/provider/handler:hash_handler_operations",
        "//score/crypto/daemon/provider/score_provider/openssl:provider_openssl_library",
        "//tests/utility",
        "@googletest//:gtest",
    ],
)

cc_test(
    name = "test_pkcs11_provider",
    srcs = ["test_pkcs11_provider.cpp"],
    data = ["//tests/test_vectors/hash:hash_test_vectors"],
    deps = [
        "//score/crypto/daemon/common",
        "//score/crypto/daemon/provider:provider_headers",
        "//score/crypto/daemon/provider/handler:hash_handler_operations",
        "//score/crypto/daemon/provider/pkcs11:provider_pkcs11_library",
        "//tests/utility",
        "//third_party/soft_hsm:libsofthsm_shared",
        "@googletest//:gtest",
    ],
)

cc_test(
    name = "test_pkcs11_multi_token",
    srcs = ["test_pkcs11_multi_token.cpp"],
    deps = [
        "//score/crypto/daemon/common",
        "//score/crypto/daemon/provider:provider_headers",
        "//score/crypto/daemon/provider:provider_manager",
        "//score/crypto/daemon/provider/pkcs11:provider_pkcs11_library",
        "//third_party/soft_hsm:libsofthsm_shared",
        "@googletest//:gtest",
    ],
)

cc_test(
    name = "test_provider_manager",
    srcs = ["test_provider_manager.cpp"],
    deps = [
        "//score/crypto/daemon/common",
        "//score/crypto/daemon/data_manager",
        "//score/crypto/daemon/provider:provider_headers",
        "//score/crypto/daemon/provider:provider_manager",
        "//score/crypto/daemon/provider/handler:context_node",
        "@googletest//:gtest_main",
    ],
)

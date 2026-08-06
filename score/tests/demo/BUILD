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

load("@rules_cc//cc:cc_test.bzl", "cc_test")

cc_test(
    name = "mac_multi_provider_demo",
    srcs = ["mac_multi_provider_demo.cpp"],
    data = [
        "//score/tests/test_vectors/key_management:key_management_test_vectors",
    ],
    target_compatible_with = select({
        "//score/crypto/src/backend:openssl_backend_active": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    deps = [
        "//score/crypto/src/daemon/key_management",
        "//score/crypto/src/daemon/provider:provider_headers",
        "//score/crypto/src/daemon/provider/score_provider/openssl:provider_openssl_library",
        "//score/crypto/src/daemon/provider/score_provider/operations/mac:score_mac_handler",
        "//third_party/openssl:openssl_shared",
        "@googletest//:gtest_main",
    ],
)

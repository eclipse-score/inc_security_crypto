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
    name = "test_openssl_cert_parser",
    srcs = ["test_openssl_cert_parser.cpp"],
    data = [
        "//score/tests/test_vectors/certificate:certificate_test_vectors",
    ],
    target_compatible_with = select({
        "//score/crypto/src/backend:openssl_backend_active": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    deps = [
        "//score/crypto/src/daemon/cert_management:cert_management_headers",
        "//score/crypto/src/daemon/provider/score_provider/openssl:openssl_cert_management_headers",
        "//score/crypto/src/daemon/provider/score_provider/openssl:openssl_cert_parser_library",
        "//third_party/openssl:openssl_shared",
        "@googletest//:gtest_main",
    ],
)

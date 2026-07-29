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
    name = "test_context_types",
    srcs = ["test_context_types.cpp"],
    deps = [
        "//score/crypto/src/api/common:crypto_common",
        "//score/crypto/src/daemon/common",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "test_operation_names",
    srcs = ["test_operation_names.cpp"],
    deps = [
        "//score/crypto/src/daemon/common:operation_names",
        "@googletest//:gtest_main",
    ],
)

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
    name = "test_key_config_manager",
    srcs = ["test_key_config_manager.cpp"],
    data = [
        "//score/crypto/tests/key_management/config:key_management_test_config",
    ],
    deps = [
        "//score/crypto/src/daemon/config",
        "//score/crypto/src/daemon/key_management",
        "//score/crypto/src/daemon/key_management:key_management_headers",
        "//score/crypto/src/daemon/provider:provider_manager",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "test_access_policy_enforcer",
    srcs = ["test_access_policy_enforcer.cpp"],
    deps = [
        "//score/crypto/src/daemon/key_management",
        "//score/crypto/src/daemon/key_management:key_management_headers",
        "@googletest//:gtest_main",
    ],
)


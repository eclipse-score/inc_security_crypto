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

# Tests parsing of provider_config (application-scoped provider resources, issue #290).
cc_test(
    name = "test_provider_resource_config",
    srcs = ["test_provider_resource_config.cpp"],
    data = [
        "//score/crypto/tests/cert_management/config:cert_management_test_config",
        "//score/crypto/tests/provider/config:provider_resource_test_configs",
    ],
    deps = [
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/config:config_types",
        "//score/crypto/src/daemon/config:flatbuffer_config_parser",
        "@googletest//:gtest_main",
    ],
)

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

load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library", "cc_test")
load("//score/tests/bazel:integration.bzl", "integration_test")

cc_library(
    name = "message_passing_adapter_integration_test_process_separatio_common",
    hdrs = ["message_passing_adapter_integration_test_process_separation_common.h"],
    deps = ["//score/crypto/src/daemon/control_plane"],
    testonly = True,
    linkstatic = True,
)

cc_binary(
    name = "message_passing_adapter_integration_test_process_separation_server",
    srcs = ["message_passing_adapter_integration_test_process_separation_server.cpp"],
    deps = [
        ":message_passing_adapter_integration_test_process_separatio_common",
        "//score/crypto/src/ipc/message_passing_adapter:message_passing_server",
        "//score/crypto/src/daemon/control_plane",
        "//score/crypto/src/daemon/config",
        "@googletest//:gtest_main",
    ],
    testonly = True,
)

cc_binary(
    name = "message_passing_adapter_integration_test_process_separation_client",
    srcs = ["message_passing_adapter_integration_test_process_separation_client.cpp"],
    deps = [
        "//score/crypto/src/ipc/message_passing_adapter:message_passing_client",
        ":message_passing_adapter_integration_test_process_separatio_common",
        "//score/crypto/src/ipc/message_passing_adapter:ipc_config",
        "@googletest//:gtest_main",
    ],
    testonly = True,
)

cc_test(
    name = "message_passing_adapter_integration_test_combined",
    srcs = ["message_passing_adapter_integration_test_combined.cpp"],
    deps = [
        "//score/crypto/src/ipc/message_passing_adapter:message_passing_client",
        "//score/crypto/src/ipc/message_passing_adapter:message_passing_server",
        "//score/crypto/src/ipc/message_passing_adapter:ipc_config",
        "//score/crypto/src/daemon/config",
        "@googletest//:gtest_main",
    ],
)

integration_test(
    name = "message_passing_adapter_integration_test_process_separation",
    size = "small",
    srcs = ["message_passing_adapter_integration_test_process_separation.py"],
    binaries = [
        ":message_passing_adapter_integration_test_process_separation_server",
        ":message_passing_adapter_integration_test_process_separation_client",
    ],
    configs = ["//score/tests/config:logging.json"],
    data = ["conftest.py"],
    libraries = [
        "//third_party/soft_hsm:softhsm_so",
        "//score/crypto/src/api/control_plane:control_plane_hdr",
        "//third_party/openssl:openssl_so",
    ],
    deps = [
        "//score/tests:common_fixtures",
        "//score/tests/utility/process_runner",
    ],
)

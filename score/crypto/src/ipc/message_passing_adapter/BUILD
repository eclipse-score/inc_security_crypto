# *******************************************************************************
# Copyright (c) 2026 Contributors to the Eclipse Foundation
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
# *******************************************************************************

load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
load("//score/tests/bazel:integration.bzl", "integration_test")

# FlatBuffers schema and codec shared by the message-passing client and server.

genrule(
    name = "generated_control",
    srcs = ["protocol/control.fbs"],
    outs = ["protocol/control_generated.h"],
    cmd = "$(location @flatbuffers//:flatc) --cpp --size-prefixed -o $(@D) $(SRCS)",
    tools = ["@flatbuffers//:flatc"],
)

cc_library(
    name = "ipc_config",
    hdrs = ["ipc_config.h"],
    linkstatic = True,
    visibility = ["//:__subpackages__"],
)

cc_library(
    name = "message_passing_protocol",
    srcs = ["protocol/flatbuffer_codec.cpp"],
    hdrs = [
        "protocol/i_control_codec.h",
        "protocol/flatbuffer_codec.h",
        ":generated_control",
    ],
    linkstatic = True,
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/src/daemon/control_plane",
        ":ipc_config",
        "@flatbuffers",
        "@score_baselibs//score/language/futurecpp",
    ],
)

cc_test(
    name = "flatbuffer_codec_test",
    srcs = ["protocol/flatbuffer_codec_test.cpp"],
    deps = [
        ":message_passing_protocol",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "message_passing_client",
    hdrs = [
        "client/client_session/client_session.h",
        "client/message_passing_control_client.h",
        "client/client_session/pending_call.h",
        "client/client_session/pending_call_registry.h",
    ],
    srcs = [
        "client/client_session/client_session.cpp",
        "client/message_passing_control_client.cpp",
        "client/client_session/pending_call.cpp",
        "client/client_session/pending_call_registry.cpp",
    ],
    linkstatic = True,
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/src/ipc/message_passing_adapter:message_passing_protocol",
        "//score/crypto/src/api/common:crypto_common",
        "//score/crypto/src/api/control_plane:control_plane_hdr",
        "//score/crypto/src/common:common_types",
        "//score/crypto/src/daemon/control_plane",
        ":ipc_config",
        "@score_baselibs//score/language/futurecpp",
        "@score_baselibs//score/mw/log",
        "@score_communication//score/message_passing:message_passing",
    ],
)

cc_library(
    name = "message_passing_server",
    srcs = [
        "server/message_passing_control_server.cpp",
        "server/server_lifecycle.cpp",
        "server/work_item_execution/fixed_worker_work_item_executor.cpp",
        "server/session/session.cpp",
        "server/session/work_item.cpp",
        "server/session/session_manager.cpp",
        "server/session/session_registry.cpp",
        "server/session/work_item_dispatcher.cpp",
    ],
    hdrs = [
        "server/message_passing_control_server.h",
        "server/server_callbacks.hpp",
        "server/server_lifecycle.h",
        "server/work_item_execution/i_work_item_submitter.h",
        "server/work_item_execution/fixed_worker_work_item_executor.h",
        "server/session/session.h",
        "server/session/work_item.h",
        "server/session/session_manager.h",
        "server/session/session_registry.h",
        "server/session/work_item_dispatcher.h",
    ],
    linkstatic = True,
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/src/ipc/message_passing_adapter:message_passing_protocol",
        "//score/crypto/src/daemon/control_plane",
        ":ipc_config",
        "@score_baselibs//score/language/futurecpp",
        "@score_baselibs//score/mw/log",
        "@score_communication//score/message_passing:message_passing",
    ],
)

cc_library(
    name = "message_passing_adapter_integration_test_process_separatio_common",
    hdrs = ["tests/message_passing_adapter_integration_test_process_separation_common.h"],
    deps = ["//score/crypto/src/daemon/control_plane"],
)

cc_binary(
    name = "message_passing_adapter_integration_test_process_separation_server",
    srcs = ["tests/message_passing_adapter_integration_test_process_separation_server.cpp"],
    deps = [
        ":message_passing_adapter_integration_test_process_separatio_common",
        ":message_passing_server",
        "//score/crypto/src/daemon/control_plane",
        "@googletest//:gtest_main",
    ],
)

cc_binary(
    name = "message_passing_adapter_integration_test_process_separation_client",
    srcs = ["tests/message_passing_adapter_integration_test_process_separation_client.cpp"],
    deps = [
        ":message_passing_client",
        ":message_passing_adapter_integration_test_process_separatio_common",
        ":ipc_config",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "message_passing_adapter_integration_test_combined",
    srcs = ["tests/message_passing_adapter_integration_test_combined.cpp"],
    deps = [
        ":message_passing_client",
        ":message_passing_server",
        ":ipc_config",
        "@googletest//:gtest_main",
    ],
)

integration_test(
    name = "message_passing_adapter_integration_test_process_separation",
    size = "small",
    srcs = ["tests/message_passing_adapter_integration_test_process_separation.py"],
    binaries = [
        ":message_passing_adapter_integration_test_process_separation_server",
        ":message_passing_adapter_integration_test_process_separation_client",
    ],
    configs = ["//score/tests/config:logging.json"],
    data = ["tests/conftest.py"],
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

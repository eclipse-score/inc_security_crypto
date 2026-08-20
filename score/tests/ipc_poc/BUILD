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

# Generate C++ and gRPC bindings from the shared POC FlatBuffer schema.
genrule(
    name = "generated_poc_control",
    srcs = ["poc_control.fbs"],
    outs = [
        "poc_control_generated.h",
        "poc_control.grpc.fb.h",
        "poc_control.grpc.fb.cc",
    ],
    cmd = "$(location @flatbuffers//:flatc) --cpp --grpc --size-prefixed -o $(@D) $(SRCS)",
    tools = ["@flatbuffers//:flatc"],
)

cc_library(
    name = "async_control_plane_service",
    hdrs = [
        "async_control_interface.h",
        "ipc_buffer.h",
        ":generated_poc_control",
    ],
    include_prefix = "tests/score_com_poc",
    deps = [
        "@flatbuffers",
        "@score_communication//score/mw/com",
    ],
)

cc_test(
    name = "poc_async",
    srcs = ["poc_async.cpp"],
    deps = [
        ":async_control_plane_service",
        ":poc_helper",
        "//score/tests/utility:runtime_measurement",
        "//score/tests/utility:process_resource_measurement",
    ],
    tags = ["manual"],
)

cc_library(
    name = "low_level_poc_deps",
    hdrs = [
        "ipc_buffer.h",
        ":generated_poc_control",
    ],
    include_prefix = "tests/score_com_poc",
    deps = [
        "@flatbuffers",
        "@score_communication//score/message_passing",
    ],
)

cc_library(
    name = "direct_socket_poc_deps",
    hdrs = [
        "ipc_buffer.h",
        ":generated_poc_control",
    ],
    include_prefix = "tests/score_com_poc",
    deps = [
        "@flatbuffers",
    ],
)

cc_library(
    name = "poc_helper",
    hdrs = [
        "ipc_buffer.h",
        "poc_helper.hpp",
    ],
    deps = [
        ":generated_poc_control",
        "@flatbuffers",
    ],
)

cc_test(
    name = "poc_low_level",
    srcs = ["poc_low_level.cpp"],
    deps = [
        ":low_level_poc_deps",
        ":poc_helper",
        "//score/tests/utility:runtime_measurement",
        "//score/tests/utility:process_resource_measurement",
    ],
    tags = ["manual"],
)

cc_test(
    name = "poc_low_level_no_reply",
    srcs = ["poc_low_level_no_reply.cpp"],
    deps = [
        ":low_level_poc_deps",
        ":poc_helper",
        "//score/tests/utility:runtime_measurement",
        "//score/tests/utility:process_resource_measurement",
    ],
    tags = ["manual"],
)

cc_test(
    name = "poc_low_level_no_reply_notify_in_thread",
    srcs = ["poc_low_level_no_reply_notify_in_thread.cpp"],
    deps = [
        ":low_level_poc_deps",
        ":poc_helper",
        "//score/tests/utility:runtime_measurement",
        "//score/tests/utility:process_resource_measurement",
    ],
    tags = ["manual"],
)

cc_test(
    name = "poc_thread_pool_queue",
    srcs = ["poc_thread_pool_queue.cpp"],
    deps = [
        "//score/tests/utility:runtime_measurement",
    ],
    tags = ["manual"],
)

cc_test(
    name = "poc_engine",
    srcs = ["poc_engine.cpp"],
    deps = [
        ":low_level_poc_deps",
        ":poc_helper",
        "//score/tests/utility:runtime_measurement",
        "//score/tests/utility:process_resource_measurement",
    ],
    tags = ["manual"],
)

cc_test(
    name = "poc_engine_sync",
    srcs = ["poc_engine_sync.cpp"],
    deps = [
        ":low_level_poc_deps",
        ":poc_helper",
        "//score/tests/utility:runtime_measurement",
        "//score/tests/utility:process_resource_measurement",
    ],
    tags = ["manual"],
)

cc_test(
    name = "poc_unix_socket",
    srcs = ["poc_unix_socket.cpp"],
    linkopts = select({
        "//platforms:is_qnx_aarch64": ["-lsocket"],
        "//platforms:is_qnx_x86_64": ["-lsocket"],
        "//conditions:default": [],
    }),
    deps = [
        ":direct_socket_poc_deps",
        ":poc_helper",
        "//score/tests/utility:runtime_measurement",
        "//score/tests/utility:process_resource_measurement",
    ],
    tags = ["manual"],
)

cc_test(
    name = "poc_qnx_message_passing",
    srcs = ["poc_qnx_message_passing.cpp"],
    target_compatible_with = select({
        "//platforms:is_qnx_aarch64": [],
        "//platforms:is_qnx_x86_64": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    deps = [
        ":direct_socket_poc_deps",
        ":poc_helper",
        "//score/tests/utility:runtime_measurement",
        "//score/tests/utility:process_resource_measurement",
    ],
    tags = ["manual"],
)

cc_library(
    name = "poc_grpc_protocol",
    srcs = [":generated_poc_control"],
    hdrs = [
        ":generated_poc_control",
    ],
    deps = [
        "@flatbuffers",
        "@grpc//:grpc++_unsecure",
    ],
)

cc_test(
    name = "poc_grpc",
    srcs = ["poc_grpc.cpp"],
    deps = [
        "//score/tests/utility:runtime_measurement",
        ":poc_helper",
        ":poc_grpc_protocol",
        "//score/tests/utility:process_resource_measurement",
        "@grpc//:grpc++_unsecure",
    ],
    tags = ["manual"],
)

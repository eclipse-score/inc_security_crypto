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

# Generate C++ header from the FlatBuffer schema.
# No --grpc flag: we only need plain C++ data tables, not gRPC stubs.
genrule(
    name = "generated_poc_control",
    srcs = ["poc_control.fbs"],
    outs = ["poc_control_generated.h"],
    cmd = "$(location @flatbuffers//:flatc) --cpp --size-prefixed -o $(@D) $(SRCS)",
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
    ],
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

cc_test(
    name = "poc_low_level",
    srcs = ["poc_low_level.cpp"],
    deps = [
        ":low_level_poc_deps",
    ],
)

cc_test(
    name = "poc_grpc",
    srcs = ["poc_grpc.cpp"],
    dynamic_deps = ["//third_party/grpc:libgrpc_shared"],
    deps = [
        "//score/crypto/src/daemon/control_plane",
        "//score/crypto/src/ipc/grpc_adapter:grpc_control_client",
        "//score/crypto/src/ipc/grpc_adapter:grpc_control_server",
    ],
)

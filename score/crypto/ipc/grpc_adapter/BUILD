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

load("@rules_cc//cc:cc_library.bzl", "cc_library")
load("@rules_cc//cc:defs.bzl", "cc_shared_library")

genrule(
    name = "generated_grpc_control_server",
    srcs = ["control.fbs"],
    outs = [
        "control_generated.h",
        "control.grpc.fb.h",
        "control.grpc.fb.cc",
    ],
    cmd = "$(location @flatbuffers//:flatc) --cpp --grpc -o $(@D) $(SRCS)",
    tools = ["@flatbuffers//:flatc"],
)

cc_library(
    name = "grpc_control_server",
    srcs = [
        "grpc_control_handler.h",
        "src/grpc_control_handler.cpp",
        "src/grpc_control_server.cpp",
        ":generated_grpc_control_server",
    ],
    hdrs = [
        "grpc_control_server.h",
    ],
    implementation_deps = [
        "@grpc//:grpc++_unsecure",
    ],
    linkstatic = True,  # Internal library should only be statically linked
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/daemon/control_plane",
        "@flatbuffers",
    ],
)

cc_library(
    name = "grpc_control_client",
    srcs = [
        "src/grpc_control_client.cpp",
        "src/grpc_id_helpers.cpp",
        ":generated_grpc_control_server",
    ],
    hdrs = [
        "grpc_control_client.h",  # No factory yet
        "src/grpc_id_helpers.h",
    ],
    implementation_deps = [
        "@grpc//:grpc++_unsecure",
    ],
    linkstatic = True,  # Internal library should only be statically linked
    visibility = [
        "//score/crypto/api:__subpackages__",
        "//score/crypto/daemon/IPC:__pkg__",
        "//tests:__subpackages__",
    ],
    deps = [
        "//score/crypto/api/control_plane",
        "//score/crypto/daemon/control_plane:request_handler_hdr",
        "@flatbuffers",
    ],
)

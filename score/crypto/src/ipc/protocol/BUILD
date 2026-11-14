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

load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
load("@score_baselibs//score/flatbuffers/bazel:codegen.bzl", "generate_cpp")

# FlatBuffers schema and codec shared by the message-passing client and server.
generate_cpp(
    name = "generated_control",
    schema = "control.fbs",
    output = "control_generated.h",
    size_prefixed = True,
)

cc_library(
    name = "protocol_config",
    hdrs = ["protocol_config.h"],
    linkstatic = True,
    visibility = ["//:__subpackages__"],
)

cc_library(
    name = "protocol",
    srcs = ["flatbuffer_codec.cpp"],
    hdrs = [
        "i_control_codec.h",
        "flatbuffer_codec.h",
        ":generated_control",
    ],
    linkstatic = True,
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/src/daemon/control_plane",
        ":protocol_config",
        "@score_baselibs//score/flatbuffers:flatbufferscpp",
        "@score_baselibs//score/language/futurecpp",
    ],
)

cc_test(
    name = "flatbuffer_codec_test",
    srcs = ["flatbuffer_codec_test.cpp"],
    deps = [
        ":protocol",
        ":protocol_config",
        "@googletest//:gtest_main",
    ],
    testonly = True,
)

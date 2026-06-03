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

load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_test")
load("@score_itf//:defs.bzl", "py_itf_test")

cc_test(
    name = "test_control_plane",
    timeout = "short",
    srcs = ["test_control_plane.cpp"],
    dynamic_deps = ["//third_party/grpc:libgrpc_shared"],
    deps = [
        "//score/crypto/api:operations",
        "//score/crypto/api/control_plane:control_plane_impl",
        "//score/crypto/daemon/control_plane",
        "//score/crypto/daemon/mediator",
        "//score/crypto/ipc/grpc_adapter:grpc_control_server",
        "@googletest//:gtest",
    ],
)

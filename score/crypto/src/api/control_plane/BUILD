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

load("@rules_cc//cc:defs.bzl", "cc_library")

cc_library(
    name = "control_plane",
    srcs = [
    ],
    hdrs = [
        "connection_factory.hpp",
        "i_connection.hpp",
    ],
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/common:common_types",
        "//score/crypto/daemon/common",
        "//score/crypto/daemon/control_plane:request_handler_hdr",
    ],
)

cc_library(
    name = "control_plane_impl",
    srcs = [
        "src/connection_factory.cpp",
        "src/connection_impl.cpp",
    ],
    hdrs = [
        "src/connection_impl.hpp",
    ],
    visibility = ["//:__subpackages__"],
    deps = [
        ":control_plane",
        "//score/crypto/daemon/control_plane",
        "//score/crypto/ipc:ipc_config",
        "//score/crypto/ipc/grpc_adapter:grpc_control_client",
        "@score_baselibs//score/mw/log",
    ],
)

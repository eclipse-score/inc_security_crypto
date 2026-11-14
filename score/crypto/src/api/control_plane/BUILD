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
    name = "control_plane_hdr",
    srcs = [
    ],
    hdrs = [
        "connection_factory.hpp",
        "i_connection.hpp",
    ],
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/src/common:common_types",
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/control_plane",
        "//score/crypto/src/daemon/control_plane:request_handler_hdr",
    ],
    linkstatic = True,
)

cc_library(
    name = "control_plane",
    srcs = [
        "src/control_plane_connection_registry.cpp",
        "src/connection_factory.cpp",
        "src/control_plane_connection.cpp",
    ],
    hdrs = [
        "src/control_plane_connection_registry.hpp",
        "src/control_plane_connection.hpp",
    ],
    visibility = ["//:__subpackages__"],
    deps = [
        ":control_plane_hdr",
        "//score/crypto/src/daemon/control_plane",
        "//score/crypto/src/ipc/message_passing_adapter:ipc_config",
        "//score/crypto/src/ipc/message_passing_adapter:message_passing_client",
        "@score_baselibs//score/mw/log",
    ],
    linkstatic = True,
)

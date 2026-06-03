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
    name = "control_operations",
    hdrs = ["control_operations.h"],
    visibility = [
        "//:__subpackages__",
    ],
    deps = ["//score/crypto/daemon/common"],
)

cc_library(
    name = "request_handler_hdr",
    hdrs = [
        "control_protocol.h",
        "i_request_handler.hpp",
    ],
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/daemon/data_manager",
        "@score_baselibs//score/mw/log",
        "@score_baselibs//score/result",
    ],
)

cc_library(
    name = "control_plane",
    srcs = [
        "src/basic_handler_chain_factory.cpp",
        "src/connection_handler.cpp",
        "src/connection_handler.hpp",
    ],
    hdrs = [
        "basic_handler_chain_factory.hpp",
        "control_protocol.h",
        "i_control_server.h",
        "i_handler_chain_factory.hpp",
        "i_request_handler.hpp",
    ],
    linkstatic = True,  # Internal library should only be statically linked
    visibility = ["//:__subpackages__"],
    deps = [
        ":control_operations",
        ":request_handler_hdr",
        "//score/crypto/daemon/config",
        "//score/crypto/daemon/data_manager",
        "//score/crypto/daemon/mediator",
        "//score/crypto/daemon/provider:provider_manager",
        "@score_baselibs//score/mw/log",
        "@score_baselibs//score/result",
    ],
)

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
    name = "mediator_operations",
    hdrs = ["mediator_operations.hpp"],
    visibility = [
        "//:__subpackages__",
    ],
    deps = ["//score/crypto/daemon/common"],
)

cc_library(
    name = "mediator",
    srcs = [
        "src/mediator_impl.cpp",
    ],
    hdrs = [
        "i_mediator.hpp",
        "src/mediator_impl.hpp",
    ],
    includes = ["."],
    visibility = ["//:__subpackages__"],
    deps = [
        ":mediator_operations",
        "//score/crypto/daemon/common",
        "//score/crypto/daemon/common:operation_names",
        "//score/crypto/daemon/config",
        "//score/crypto/daemon/control_plane:request_handler_hdr",
        "//score/crypto/daemon/data_manager",
        "//score/crypto/daemon/key_management",
        "//score/crypto/daemon/key_management:key_management_headers",
        "//score/crypto/daemon/provider:provider_headers",
        "//score/crypto/daemon/provider:provider_manager",
    ],
)

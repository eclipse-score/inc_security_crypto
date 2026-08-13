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
    name = "i_shm_factory",
    hdrs = ["i_shm_factory.hpp"],
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/src/api/common:crypto_common",
        "//score/crypto/src/common:common_types",
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/data_manager",
        "//score/crypto/src/daemon/mediator:mediator_operations",
        "@score_baselibs//score/memory/shared",
    ],
)

cc_library(
    name = "data_plane",
    srcs = [
        "src/base_shm_factory.cpp",
        "src/shm_data_node.cpp",
        "src/shm_registry.cpp",
        "src/shm_request_handler.cpp",
    ],
    hdrs = [
        "i_shm_data_node.hpp",
        "i_shm_registry.hpp",
        "src/base_shm_factory.hpp",
        "src/shm_data_node.hpp",
        "src/shm_registry.hpp",
        "src/shm_request_handler.hpp",
    ],
    visibility = ["//:__subpackages__"],
    deps = [
        ":i_shm_factory",
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/control_plane:request_handler_hdr",
        "//score/crypto/src/daemon/data_manager",
        "@score_baselibs//score/memory/shared",
        "@score_baselibs//score/mw/log",
    ],
)

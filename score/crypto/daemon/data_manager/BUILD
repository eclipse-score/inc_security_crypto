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

cc_library(
    name = "data_manager",
    srcs = [
        "src/data_manager.cpp",
        "src/data_node.cpp",
        "src/data_node_manager_token.hpp",
    ],
    hdrs = [
        "i_data_manager.hpp",
        "data_node.hpp",
        "data_node_accessor.hpp",
        # Public due to missing Factory
        "data_manager.hpp",
    ],
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/common:common_types",
        "//score/crypto/daemon/common",
        "//score/crypto/daemon/provider/handler:handler_headers",
        "@score_baselibs//score/mw/log",
    ],
)

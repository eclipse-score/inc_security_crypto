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

# MAC executor + abstract base MAC handler for the score interface family.
cc_library(
    name = "score_mac_handler",
    srcs = [
        "src/mac_executor.cpp",
        "src/score_mac_handler.cpp",
    ],
    hdrs = [
        "mac_executor.hpp",
        "score_mac_handler.hpp",
    ],
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/daemon/common",
        "//score/crypto/daemon/provider/handler:handler_headers",
        "//score/crypto/daemon/provider/handler:handler_utils_impl",
        "//score/crypto/daemon/provider/handler:mac_handler_operations",
    ],
)

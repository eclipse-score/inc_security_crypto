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

# Random executor + abstract base random handler for the score interface family.
cc_library(
    name = "score_random_handler",
    srcs = [
        "src/random_executor.cpp",
        "src/score_random_handler.cpp",
    ],
    hdrs = [
        "random_executor.hpp",
        "score_random_handler.hpp",
    ],
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/provider/handler:handler_headers",
        "//score/crypto/src/daemon/provider/handler:handler_utils_impl",
        "//score/crypto/src/daemon/provider/handler:random_handler_operations",
    ],
)

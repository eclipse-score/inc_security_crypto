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

# Hash executor + abstract base hash handler for the score interface family.
cc_library(
    name = "score_hash_handler",
    srcs = [
        "src/hash_executor.cpp",
        "src/score_hash_handler.cpp",
    ],
    hdrs = [
        "hash_executor.hpp",
        "score_hash_handler.hpp",
    ],
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/daemon/common",
        "//score/crypto/daemon/common:algorithm_info",
        "//score/crypto/daemon/provider/handler:handler_headers",
        "//score/crypto/daemon/provider/handler:handler_utils_impl",
        "//score/crypto/daemon/provider/handler:hash_handler_operations",
    ],
)

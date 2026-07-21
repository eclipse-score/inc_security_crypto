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
    name = "common_types",
    srcs = [
        "types.hpp",
    ],
    copts = [
        # Use baselibs expected implementation by default
        "-DSTD_LIB_CPP17=0",
    ],
    visibility = ["//:__subpackages__"],
    # Default: use baselibs/futurecpp expected
    # To switch to C++17 std lib: remove the deps below and set -DSTD_LIB_CPP17=1
    deps = [
        # Use results for deatils/expected, as it is not directly visible
        "@score_baselibs//score/result",
    ],
)

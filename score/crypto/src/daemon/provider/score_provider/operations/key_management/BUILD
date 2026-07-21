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

# Abstract base key management handler for the score interface family.
cc_library(
    name = "score_key_management_handler",
    srcs = ["src/score_key_management_handler.cpp"],
    hdrs = ["score_key_management_handler.hpp"],
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/daemon/provider/executors:key_mgmt_executor",
        "//score/crypto/daemon/provider/handler:handler_headers",
    ],
)

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
    name = "key_mgmt_executor",
    srcs = ["src/key_mgmt_executor.cpp"],
    hdrs = [
        "key_mgmt_context.hpp",
        "key_mgmt_executor.hpp",
        "key_mgmt_request_parser.hpp",
    ],
    visibility = [
        "//score/crypto/daemon/provider:__subpackages__",
        "//tests:__subpackages__",
    ],
    deps = [
        "//score/crypto/daemon/common",
        "//score/crypto/daemon/key_management",
        "//score/crypto/daemon/provider/handler:handler_headers",
    ],
)

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
    name = "key_exporter",
    srcs = ["key_exporter.cpp"],
    hdrs = ["key_exporter.hpp"],
    visibility = [
        "//score/crypto/src/daemon/provider:__subpackages__",
        "//score/crypto/tests:__subpackages__",
    ],
    deps = [
        "//score/crypto/src/daemon/key_management:key_management_headers",
    ],
)

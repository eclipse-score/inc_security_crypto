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

# Abstract base handler factory for the score interface family.
cc_library(
    name = "score_handler_factory",
    srcs = ["src/score_handler_factory.cpp"],
    hdrs = ["score_handler_factory.hpp"],
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/daemon/common",
        "//score/crypto/daemon/key_management",
        "//score/crypto/daemon/provider/handler:crypto_handler_factory_headers",
        "@score_baselibs//score/result",
    ],
)

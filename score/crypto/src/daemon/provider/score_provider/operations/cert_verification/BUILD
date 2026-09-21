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

# CERT:VERIFICATION executor + abstract base handler for the score interface family.
#
# Executor and handler are compiled together to avoid a circular header dependency
# (executor includes the handler forward declaration; handler owns the executor).
cc_library(
    name = "score_cert_verification_handler",
    srcs = [
        "src/cert_verification_executor.cpp",
        "src/score_cert_verification_handler.cpp",
    ],
    hdrs = [
        "cert_verification_executor.hpp",
        "score_cert_verification_handler.hpp",
    ],
    target_compatible_with = select({
        "//score/crypto/src/backend:score_backend_enabled": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/src/daemon/cert_management",
        "//score/crypto/src/daemon/provider/cert_management:cert_parser_headers",
        "//score/crypto/src/daemon/provider/executors:cert_mgmt_context",
        "//score/crypto/src/daemon/provider/handler:cert_verification_operations",
        "//score/crypto/src/daemon/provider/handler:handler_headers",
        "@score_baselibs//score/mw/log",
    ],
)

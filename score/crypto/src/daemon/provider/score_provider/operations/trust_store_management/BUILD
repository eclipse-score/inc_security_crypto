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

# CERT:TRUST_STORE context handler — delegates to TrustStoreManagementExecutor.
cc_library(
    name = "score_trust_store_management_handler",
    srcs = ["src/score_trust_store_management_handler.cpp"],
    hdrs = ["score_trust_store_management_handler.hpp"],
    target_compatible_with = select({
        "//score/crypto/src/backend:score_backend_enabled": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/src/daemon/provider/executors:trust_store_mgmt_executor",
        "//score/crypto/src/daemon/provider/handler:handler_headers",
    ],
)

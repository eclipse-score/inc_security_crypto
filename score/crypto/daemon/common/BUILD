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
    name = "common",
    hdrs = [
        "actors.hpp",
        "daemon_error.hpp",
        "secure_memory.hpp",
        "types.hpp",
    ],
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/mw/crypto/api/common:crypto_common",
        "@score_baselibs//score/result",
    ],
)

# Header-only utility: algorithm sizing tables for hash, MAC, and key algorithms.
cc_library(
    name = "algorithm_info",
    hdrs = ["algorithm_info.hpp"],
    visibility = ["//:__subpackages__"],
)

# Header-only utility: human-readable names for OperationActor / OperationAction values.
# Depends on the three operation-constants headers (each only deps on :common).
cc_library(
    name = "operation_names",
    hdrs = ["operation_names.hpp"],
    visibility = ["//:__subpackages__"],
    deps = [
        ":common",
        "//score/crypto/daemon/key_management:key_management_operations",
        "//score/crypto/daemon/provider/handler:hash_handler_operations",
        "//score/crypto/daemon/provider/handler:mac_handler_operations",
        "@score_baselibs//score/mw/log",
    ],
)

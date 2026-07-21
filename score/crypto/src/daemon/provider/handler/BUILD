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
    name = "handler_headers",
    hdrs = [
        "handler_init_params.hpp",
        "i_handler.hpp",
    ],
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/src/api/common:crypto_common",
        "//score/crypto/src/common:common_types",
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/key_management:key_handler_iface",
    ],
)

cc_library(
    name = "crypto_handler_factory_headers",
    hdrs = ["i_crypto_handler_factory.hpp"],
    visibility = ["//visibility:public"],
    deps = [
        ":handler_headers",
        ":handler_utils_hdr",
        "//score/crypto/src/daemon/common",
        "@score_baselibs//score/result",
    ],
)

# Handler utilities header library
cc_library(
    name = "handler_utils_hdr",
    hdrs = ["src/handler_utils.hpp"],
    visibility = [
        "//score/crypto/src/daemon/provider:__subpackages__",
        "//score/crypto/src/daemon/src/provider:__subpackages__",
    ],
    deps = [
        "//score/crypto/src/common:common_types",
        "//score/crypto/src/daemon/common",
    ],
)

# Handler utilities implementation library
cc_library(
    name = "handler_utils_impl",
    srcs = ["src/handler_utils.cpp"],
    hdrs = ["src/handler_utils.hpp"],
    visibility = [
        "//score/crypto/src/daemon/provider:__subpackages__",
        "//score/crypto/src/daemon/src/provider:__subpackages__",
    ],
    deps = [
        ":handler_utils_hdr",
        "//score/crypto/src/daemon/common",
    ],
)

# Hash handler operations header-only library
cc_library(
    name = "hash_handler_operations",
    hdrs = ["operations/hash_handler_operations.hpp"],
    visibility = [
        "//:__subpackages__",
    ],
    deps = ["//score/crypto/src/daemon/common"],
)

cc_library(
    name = "context_node",
    srcs = ["src/context_data_node.cpp"],
    hdrs = ["context_data_node.hpp"],
    visibility = ["//visibility:public"],
    deps = [
        ":handler_headers",
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/data_manager",
        "//score/crypto/src/daemon/key_management:key_management_headers",
    ],
)

# MAC handler operations header-only library
cc_library(
    name = "mac_handler_operations",
    hdrs = ["operations/mac_handler_operations.hpp"],
    visibility = ["//:__subpackages__"],
    deps = ["//score/crypto/src/daemon/common"],
)

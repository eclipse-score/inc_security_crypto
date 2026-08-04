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
    name = "provider_headers",
    hdrs = [
        "i_provider.hpp",
        "i_provider_factory.hpp",
        "provider_manager.hpp",
    ],
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/config",
        "//score/crypto/src/daemon/provider/handler:context_node",
        "//score/crypto/src/daemon/provider/handler:crypto_handler_factory_headers",
    ],
)

cc_library(
    name = "provider_manager",
    srcs = ["src/provider_manager.cpp"],
    visibility = ["//:__subpackages__"],
    deps = [
        ":provider_headers",
    ],
)

cc_library(
    name = "provider_manager_factory",
    srcs = ["src/provider_manager_factory.cpp"],
    hdrs = ["provider_manager_factory.hpp"],
    implementation_deps = select({
        "//score/crypto/src/backend:score_backend_enabled": [
            "//score/crypto/src/backend:score_backend_defines",
        ],
        "//conditions:default": [],
    }) + select({
        "//score/crypto/src/backend:pkcs11_enabled": [
            "//score/crypto/src/backend:pkcs11_backend_defines",
        ],
        "//conditions:default": [],
    }),
    visibility = ["//:__subpackages__"],
    deps = [
        ":provider_headers",
        ":provider_manager",
    ] + select({
        "//score/crypto/src/backend:score_backend_enabled": ["//score/crypto/src/daemon/provider/score_provider:score_provider_factory"],
        "//conditions:default": [],
    }) + select({
        "//score/crypto/src/backend:pkcs11_enabled": ["//score/crypto/src/daemon/provider/pkcs11:provider_pkcs11_factory"],
        "//conditions:default": [],
    }),
)

#-----------------------------------#
# Unit tests for the provider manager
#-----------------------------------#

cc_test(
    name = "provider_manager_unit_test",
    srcs = ["src/provider_manager_test.cpp"],
    deps = [
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/data_manager",
        "//score/crypto/src/daemon/provider:provider_headers",
        "//score/crypto/src/daemon/provider:provider_manager",
        "@googletest//:gtest_main",
    ],
)

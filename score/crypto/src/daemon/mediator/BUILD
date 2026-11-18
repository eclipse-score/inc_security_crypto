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

load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")

cc_library(
    name = "mediator_operations",
    hdrs = ["mediator_operations.hpp"],
    visibility = [
        "//:__subpackages__",
    ],
    deps = [
        "//score/crypto/src/api/types",
        "//score/crypto/src/common:common_types",
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/control_plane:request_handler_hdr",
    ],
)

cc_library(
    name = "context_algorithm",
    hdrs = ["context_algorithm.hpp"],
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/common:algorithm_catalog",
    ],
)

cc_test(
    name = "provider_type_preference_test",
    srcs = ["provider_type_preference_test.cpp"],
    deps = [
        ":mediator_operations",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "mediator_operations_test",
    srcs = ["mediator_operations_test.cpp"],
    deps = [
        ":mediator_operations",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "mediator_resource_resolution_test",
    srcs = ["mediator_resource_resolution_test.cpp"],
    deps = [
        ":mediator",
        ":mediator_operations",
        "//score/crypto/src/api/types",
        "//score/crypto/src/daemon/config:config_types",
        "//score/crypto/src/daemon/control_plane:request_handler_hdr",
        "//score/crypto/src/daemon/data_manager",
        "//score/crypto/src/daemon/key_management",
        "//score/crypto/src/daemon/key_management:key_management_headers",
        "//score/crypto/src/daemon/provider:provider_headers",
        "//score/crypto/src/daemon/provider:provider_manager",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "context_algorithm_test",
    srcs = ["context_algorithm_test.cpp"],
    deps = [
        ":context_algorithm",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "mediator",
    srcs = [
        "src/mediator_impl.cpp",
    ],
    hdrs = [
        "i_mediator.hpp",
        "src/mediator_impl.hpp",
    ],
    includes = ["."],
    visibility = ["//:__subpackages__"],
    deps = [
        ":context_algorithm",
        ":mediator_operations",
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/common:algorithm_catalog",
        "//score/crypto/src/daemon/common:key_compatibility",
        "//score/crypto/src/daemon/common:operation_names",
        "//score/crypto/src/daemon/config",
        "//score/crypto/src/daemon/control_plane:request_handler_hdr",
        "//score/crypto/src/daemon/data_manager",
        "//score/crypto/src/daemon/data_plane",
        "//score/crypto/src/daemon/key_management",
        "//score/crypto/src/daemon/key_management:key_management_headers",
        "//score/crypto/src/daemon/provider:provider_headers",
        "//score/crypto/src/daemon/provider:provider_manager",
    ],
)

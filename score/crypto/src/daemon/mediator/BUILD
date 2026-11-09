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
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/control_plane:request_handler_hdr",
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

cc_library(
    name = "context_algorithm",
    hdrs = ["context_algorithm.hpp"],
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/common/context:context_types",
        "//score/crypto/src/daemon/common:algorithm_catalog",
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

cc_test(
    name = "context_creation_decoder_test",
    srcs = ["src/context_creation_decoder_test.cpp"],
    deps = [
        ":mediator",
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/common/context:context_registration",
        "//score/crypto/src/daemon/common/context:context_types",
        "//score/crypto/src/daemon/control_plane:request_handler_hdr",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "mediator_test_doubles",
    testonly = True,
    hdrs = ["src/mediator_test_doubles.hpp"],
    deps = [
        "//score/crypto/src/api/common:crypto_common",
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/common:algorithm_catalog",
        "//score/crypto/src/daemon/common/context:context_registration",
        "//score/crypto/src/daemon/common/context:handler_headers",
        "//score/crypto/src/daemon/control_plane:request_handler_hdr",
        "//score/crypto/src/daemon/data_manager",
        "//score/crypto/src/daemon/provider:provider_headers",
        "//score/crypto/src/daemon/provider/handler:crypto_handler_factory_headers",
        "@score_baselibs//score/result",
    ],
)

cc_test(
    name = "provider_arbiter_test",
    srcs = ["src/provider_arbiter_test.cpp"],
    deps = [
        ":mediator",
        ":mediator_test_doubles",
        "//score/crypto/src/daemon/config",
        "//score/crypto/src/daemon/provider:provider_manager",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "context_assembler_test",
    srcs = ["src/context_assembler_test.cpp"],
    deps = [
        ":mediator",
        ":mediator_test_doubles",
        "//score/crypto/src/daemon/key_management",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "mediator_factory_test",
    srcs = ["src/mediator_factory_test.cpp"],
    deps = [
        ":mediator",
        ":mediator_operations",
        ":mediator_test_doubles",
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/config",
        "//score/crypto/src/daemon/control_plane:request_handler_hdr",
        "//score/crypto/src/daemon/provider:provider_manager",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "mediator_impl_test",
    srcs = ["src/mediator_impl_test.cpp"],
    deps = [
        ":mediator",
        ":mediator_operations",
        ":mediator_test_doubles",
        "//score/crypto/src/api/types:types",
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/config",
        "//score/crypto/src/daemon/control_plane:request_handler_hdr",
        "//score/crypto/src/daemon/provider:provider_manager",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "mediator",
    srcs = [
        "src/context_assembler.cpp",
        "src/context_creation_decoder.cpp",
        "src/mediator_factory.cpp",
        "src/mediator_impl.cpp",
        "src/provider_arbiter.cpp",
    ],
    hdrs = [
        "i_mediator.hpp",
        "mediator_factory.hpp",
        "mediator_impl.hpp",
        "src/context_assembler.hpp",
        "src/context_creation_decoder.hpp",
        "src/provider_arbiter.hpp",
    ],
    visibility = ["//:__subpackages__"],
    deps = [
        ":context_algorithm",
        ":mediator_operations",
        "//score/crypto/src/common:common_types",
        "//score/crypto/src/daemon/common/context:context_mode",
        "//score/crypto/src/daemon/common/context:context_types",
        "//score/crypto/src/daemon/common/context:context_registration",
        "//score/crypto/src/api/types:types",
        "//score/crypto/src/daemon/common:algorithm_catalog",
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/common:key_compatibility",
        "//score/crypto/src/daemon/common:operation_names",
        "//score/crypto/src/daemon/common/context:context_node",
        "//score/crypto/src/daemon/common/context:handler_headers",
        "//score/crypto/src/daemon/config",
        "//score/crypto/src/daemon/control_plane:request_handler_hdr",
        "//score/crypto/src/daemon/data_manager",
        "//score/crypto/src/daemon/data_plane",
        "//score/crypto/src/daemon/key_management",
        "//score/crypto/src/daemon/key_management:key_handler_iface",
        "//score/crypto/src/daemon/key_management:key_management_headers",
        "//score/crypto/src/daemon/provider:provider_headers",
        "//score/crypto/src/daemon/provider:provider_manager",
        "//score/crypto/src/daemon/provider/handler:crypto_handler_factory_headers",
    ],
)

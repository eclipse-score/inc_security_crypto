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

# Handler contract shared by the mediator, providers, and data management.
# Does not depend on key_management; IKeyHandler is forward-declared.
cc_library(
    name = "handler_headers",
    hdrs = [
        "handler_init_params.hpp",
        "i_handler.hpp",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//score/crypto/src/api/common:crypto_common",
        "//score/crypto/src/api/types:types",
        "//score/crypto/src/common:common_types",
        "//score/crypto/src/daemon/common",
    ],
)

cc_library(
    name = "context_node",
    srcs = ["src/context_data_node.cpp"],
    hdrs = ["context_data_node.hpp"],
    visibility = ["//visibility:public"],
    deps = [
        ":handler_headers",
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/common:algorithm_catalog",
        "//score/crypto/src/daemon/data_manager",
    ],
)

# Context mode: the operation direction and mode a context is bound to at creation.
cc_library(
    name = "context_mode",
    hdrs = ["context_mode.hpp"],
    visibility = ["//visibility:public"],
    deps = [
        "//score/crypto/src/api/types:types",
        "//score/crypto/src/common:common_types",
        "//score/crypto/src/daemon/common",
    ],
)

# Canonical context-type identifiers, the key permission each type consumes, and the
# provider capability its scope requires.
cc_library(
    name = "context_types",
    hdrs = ["context_types.hpp"],
    visibility = ["//visibility:public"],
    deps = [
        ":context_mode",
        "//score/crypto/src/api/types:types",
        "//score/crypto/src/daemon/common",
    ],
)

cc_test(
    name = "context_types_test",
    srcs = ["context_types_test.cpp"],
    deps = [
        ":context_mode",
        ":context_types",
        "//score/crypto/src/api/common:crypto_common",
        "@googletest//:gtest_main",
    ],
)

# Generic keyed registry filled at startup and read afterwards.
cc_library(
    name = "keyed_registry",
    hdrs = ["keyed_registry.hpp"],
    visibility = ["//visibility:public"],
)

# Resource resolver contract implemented by subsystems that serve RESOLVE_RESOURCE.
cc_library(
    name = "resource_resolver",
    hdrs = ["i_resource_resolver.hpp"],
    visibility = ["//visibility:public"],
    deps = [
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/control_plane:request_handler_hdr",
    ],
)

# Registration contracts used by the mediator: context factories and mediator queries.
cc_library(
    name = "context_registration",
    hdrs = [
        "context_creation_request.hpp",
        "i_context_factory.hpp",
        "i_mediator_query.hpp",
        "i_mediator_registrar.hpp",
    ],
    visibility = ["//visibility:public"],
    deps = [
        ":keyed_registry",
        ":context_mode",
        ":handler_headers",
        ":resource_resolver",
        "//score/crypto/src/api/types:types",
        "//score/crypto/src/common:common_types",
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/common:algorithm_catalog",
        "//score/crypto/src/daemon/control_plane:request_handler_hdr",
    ],
)

cc_test(
    name = "keyed_registry_test",
    srcs = ["keyed_registry_test.cpp"],
    deps = [
        ":keyed_registry",
        "@googletest//:gtest_main",
    ],
)

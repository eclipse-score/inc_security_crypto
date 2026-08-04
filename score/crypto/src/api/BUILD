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
    name = "operations",
    visibility = [
        "//:__subpackages__",
    ],
    deps = [
        "//score/crypto/src/daemon/control_plane:control_operations",
        "//score/crypto/src/daemon/key_management:key_management_operations",
        "//score/crypto/src/daemon/mediator:mediator_operations",
        "//score/crypto/src/daemon/provider/handler:hash_handler_operations",
        "//score/crypto/src/daemon/provider/handler:mac_handler_operations",
    ],
)

cc_library(
    name = "crypto_stack",
    srcs = [
        "src/crypto_context_impl.cpp",
        "src/crypto_context_impl.hpp",
        "src/crypto_stack_factory.cpp",
        "src/crypto_stack_impl.cpp",
        "src/crypto_stack_impl.hpp",
        "src/provider_type_converter.hpp",
    ],
    hdrs = [
        "crypto_stack_factory.hpp",
        "i_crypto_context.hpp",
        "i_crypto_stack.hpp",
    ],
    includes = ["."],
    visibility = ["//visibility:public"],
    deps = [
        "//score/crypto/src/api:operations",
        "//score/crypto/src/api/common:crypto_common",
        "//score/crypto/src/api/config:context_configs",
        "//score/crypto/src/api/contexts:context_bases",
        "//score/crypto/src/api/contexts:crypto_contexts",
        "//score/crypto/src/api/contexts:crypto_contexts_impl",
        "//score/crypto/src/api/control_plane:control_plane_impl",
        "//score/crypto/src/api/objects:crypto_objects",
        "@score_baselibs//score/language/futurecpp",
        "@score_baselibs//score/result",
    ],
)

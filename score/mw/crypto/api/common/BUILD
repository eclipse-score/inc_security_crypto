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
    name = "crypto_common",
    srcs = [
        "src/crypto_resource_guard.cpp",
        "src/crypto_resource_guard_factory.hpp",  # implementation-private; not exposed via hdrs
        "src/error_domain.cpp",
        "src/i_release_callback.hpp",  # implementation-private; not exposed via hdrs
    ],
    hdrs = [
        "crypto_resource_guard.hpp",
        "error_domain.hpp",
        "fixed_capacity_string.hpp",
        "i_memory_allocator.hpp",
        "i_memory_region.hpp",
        "types.hpp",
    ],
    includes = ["."],
    visibility = ["//visibility:public"],
    deps = [
        "@score_baselibs//score/language/futurecpp",
        "@score_baselibs//score/result",
    ],
)

# Internal target for IPC-layer code that implements IReleaseCallback.
# Application code must not depend on this target.
cc_library(
    name = "release_callback_iface",
    hdrs = ["src/i_release_callback.hpp"],
    includes = ["."],
    visibility = [
        "//score/crypto:__subpackages__",
        "//score/mw/crypto:__subpackages__",
    ],
    deps = [
        "@score_baselibs//score/result",
    ],
)

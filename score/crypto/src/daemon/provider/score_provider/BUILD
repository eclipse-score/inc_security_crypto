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

# Abstract base provider for the score interface family.
cc_library(
    name = "score_provider",
    srcs = ["src/score_provider.cpp"],
    hdrs = ["score_provider.hpp"],
    target_compatible_with = select({
        "//score/crypto/src/backend:score_backend_enabled": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/src/daemon/provider:provider_headers",
        "//score/crypto/src/daemon/provider/handler:crypto_handler_factory_headers",
    ],
)

cc_library(
    name = "score_provider_config",
    srcs = ["src/score_provider_config.cpp"],
    hdrs = ["score_provider_config.hpp"],
    target_compatible_with = select({
        "//score/crypto/src/backend:score_backend_enabled": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/src/common:common_types",
        "//score/crypto/src/daemon/common",
    ],
)

# Backend adapter interface (used by backend adapters to register with score provider).
cc_library(
    name = "score_backend_adapter",
    hdrs = ["score_backend_adapter.hpp"],
    target_compatible_with = select({
        "//score/crypto/src/backend:score_backend_enabled": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/src/daemon/provider:provider_headers",
    ],
)

cc_library(
    name = "provider_iav_primula_library",
    srcs = [
        "iav_primula/iav_primula_provider.cpp",
        "iav_primula/operations/factory/iav_primula_handler_factory.cpp",
        "iav_primula/key_management/iav_primula_key_factory.cpp",
        "iav_primula/key_management/iav_primula_key_handler.cpp",
        "iav_primula/operations/sign/iav_primula_sign_handler.cpp",
        "iav_primula/operations/verify/iav_primula_verify_handler.cpp",
        "iav_primula/operations/kem/iav_primula_kem_handler.cpp",
    ],
    hdrs = [
        "iav_primula/iav_primula_provider.hpp",
        "iav_primula/operations/factory/iav_primula_handler_factory.hpp",
        "iav_primula/key_management/iav_primula_key_factory.hpp",
        "iav_primula/key_management/iav_primula_key_handler.hpp",
        "iav_primula/operations/sign/iav_primula_sign_handler.hpp",
        "iav_primula/operations/verify/iav_primula_verify_handler.hpp",
        "iav_primula/operations/kem/iav_primula_kem_handler.hpp",
    ],
    target_compatible_with = select({
        "//score/crypto/src/backend:primula_backend_active": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    visibility = [
        "//score/crypto/src/backend/score_provider/iav_primula:__pkg__",
        "//score/crypto/src/daemon/provider/score_provider:__subpackages__",
    ],
    deps = [
        "//score/crypto/src/daemon/common:algorithm_info",
        "//score/crypto/src/daemon/key_management:key_management_headers",
        "//score/crypto/src/daemon/provider/handler:crypto_handler_factory_headers",
        "//score/crypto/src/daemon/provider/score_provider",
        "//score/crypto/src/daemon/provider/score_provider/operations/factory:score_handler_factory",
        "//score/crypto/src/daemon/provider/score_provider/operations/kem:score_kem_handler",
        "//score/crypto/src/daemon/provider/score_provider/operations/sign:score_sign_handler",
        "//score/crypto/src/daemon/provider/score_provider/operations/verify:score_verify_handler",
        "//score/iav_primula:iav_primula_ffi_headers",
        "//score/iav_primula:iav_primula_staticlib",
    ],
)

# Top-level factory for the score interface family.
cc_library(
    name = "score_provider_factory",
    srcs = [
        "src/score_provider_factory.cpp",
    ],
    hdrs = ["score_provider_factory.hpp"],
    implementation_deps = [
        "//score/crypto/src/backend/score_provider:backend",  # Selected Score backends
    ],
    target_compatible_with = select({
        "//score/crypto/src/backend:score_backend_enabled": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    visibility = ["//:__subpackages__"],
    deps = [
        ":score_provider",
        ":score_provider_config",
        "//score/crypto/src/daemon/provider:provider_headers",
    ],
)

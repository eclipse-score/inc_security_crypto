# *******************************************************************************
# Copyright (c) 2026 Contributors to the Eclipse Foundation
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
# *******************************************************************************

load("@rules_cc//cc:defs.bzl", "cc_library")

cc_library(
    name = "provider_iav_primula_library",
    srcs = [
        "iav_primula_provider.cpp",
        "operations/factory/iav_primula_handler_factory.cpp",
        "key_management/iav_primula_key_factory.cpp",
        "key_management/iav_primula_key_handler.cpp",
        "operations/sign/iav_primula_sign_handler.cpp",
        "operations/verify/iav_primula_verify_handler.cpp",
        "operations/kem/iav_primula_kem_handler.cpp",
    ],
    hdrs = [
        "iav_primula_provider.hpp",
        "operations/factory/iav_primula_handler_factory.hpp",
        "key_management/iav_primula_key_factory.hpp",
        "key_management/iav_primula_key_handler.hpp",
        "operations/sign/iav_primula_sign_handler.hpp",
        "operations/verify/iav_primula_verify_handler.hpp",
        "operations/kem/iav_primula_kem_handler.hpp",
    ],
    target_compatible_with = select({
        "//score/crypto/src/backend:primula_backend_active": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    visibility = [
        "//score/crypto/src/backend/score_provider/iav_primula:__pkg__",
        "//score/crypto/src/daemon/provider/score_provider/iav_primula:__subpackages__",
    ],
    deps = [
        "//score/crypto/src/daemon/common:algorithm_info",
        "//score/crypto/src/daemon/key_management:key_management_headers",
        "//score/crypto/src/daemon/provider/handler:crypto_handler_factory_headers",
        "//score/crypto/src/daemon/provider/score_provider:score_provider",
        "//score/crypto/src/daemon/provider/score_provider/operations/factory:score_handler_factory",
        "//score/crypto/src/daemon/provider/score_provider/operations/kem:score_kem_handler",
        "//score/crypto/src/daemon/provider/score_provider/operations/sign:score_sign_handler",
        "//score/crypto/src/daemon/provider/score_provider/operations/verify:score_verify_handler",
        "//score/iav_primula:iav_primula_ffi_headers",
        "//score/iav_primula:iav_primula_staticlib",
    ],
)

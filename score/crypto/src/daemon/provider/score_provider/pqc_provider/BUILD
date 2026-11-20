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
    name = "provider_pqc_provider_library",
    srcs = [
        "pqc_provider.cpp",
        "operations/factory/pqc_provider_handler_factory.cpp",
        "key_management/pqc_provider_key_factory.cpp",
        "key_management/pqc_provider_key_handler.cpp",
        "key_management/pqc_provider_shared_secret_handler.cpp",
        "operations/sign/pqc_provider_sign_handler.cpp",
        "operations/verify/pqc_provider_verify_handler.cpp",
    ],
    hdrs = [
        "pqc_provider_algorithm.hpp",
        "pqc_provider.hpp",
        "operations/factory/pqc_provider_handler_factory.hpp",
        "key_management/pqc_provider_key_factory.hpp",
        "key_management/pqc_provider_key_handler.hpp",
        "key_management/pqc_provider_shared_secret_handler.hpp",
        "operations/sign/pqc_provider_sign_handler.hpp",
        "operations/verify/pqc_provider_verify_handler.hpp",
    ],
    target_compatible_with = select({
        "//score/crypto/src/backend:pqc_provider_backend_active": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    visibility = [
        "//score/crypto/src/backend/score_provider/pqc_provider:__pkg__",
        "//score/crypto/src/daemon/provider/score_provider/pqc_provider:__subpackages__",
    ],
    deps = [
        "//score/crypto/src/daemon/common:algorithm_info",
        "//score/crypto/src/daemon/key_management:key_management_headers",
        "//score/crypto/src/daemon/provider/handler:crypto_handler_factory_headers",
        "//score/crypto/src/daemon/provider/score_provider:score_provider",
        "//score/crypto/src/daemon/provider/score_provider/operations/factory:score_handler_factory",
        "//score/crypto/src/daemon/provider/score_provider/operations/key_management:score_key_management_handler",
        "//score/crypto/src/daemon/provider/score_provider/operations/sign:score_sign_handler",
        "//score/crypto/src/daemon/provider/score_provider/operations/verify:score_verify_handler",
        "//score/pqc_provider:pqc_provider_ffi_headers",
        "//score/pqc_provider:pqc_provider_staticlib",
    ],
)

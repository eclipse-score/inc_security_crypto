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

# ============================================================================
# OpenSSL score-provider backend
#
# Enable/disable via bool_flag at build time (default: enabled):
#   --//score/crypto/src/backend:score_crypto_score_openssl_enabled=False
#
# Three-target pattern (same pattern for every score-provider backend):
#   openssl_backend_adapter  — full implementation, always compiled when enabled
#   openssl_backend_define   — preprocessor define only (lightweight)
#   openssl_backend          — conditional aggregate: define + adapter
#
# All select() arms check the POSITIVE (enabled=True) case.
# //conditions:default represents the inactive state.
#
# Consumers:
#   score_backend_headers (score_provider/BUILD) depends on openssl_backend_define
#   all_score_backends     (score_provider/BUILD)  depends on openssl_backend
# ============================================================================

cc_library(
    name = "openssl_backend_adapter",
    srcs = ["openssl_backend_adapter.cpp"],
    hdrs = ["openssl_backend_adapter.hpp"],
    target_compatible_with = select({
        "//score/crypto/src/backend:openssl_backend_active": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    visibility = ["//score/crypto/src/backend/score_provider:__pkg__"],
    deps = [
        "//score/crypto/src/daemon/provider/score_provider:score_backend_adapter",
        "//score/crypto/src/daemon/provider/score_provider/openssl:provider_openssl_library",
    ],
)

# Lightweight: supplies SCORE_BACKEND_OPENSSL_ENABLED define.
# No adapter deps — safe to use wherever only the define is needed.
cc_library(
    name = "openssl_backend_define",
    defines = ["SCORE_BACKEND_OPENSSL_ENABLED=1"],
    target_compatible_with = select({
        "//score/crypto/src/backend:openssl_backend_active": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    visibility = [
        "//score/crypto/src/backend:__pkg__",
        "//score/crypto/src/backend/score_provider:__pkg__",
        "//score/tests/backend_symbol_check:__pkg__",
    ],
)

# Aggregate: define + adapter. Only active_score_backends should depend on this target.
cc_library(
    name = "openssl_backend",
    target_compatible_with = select({
        "//score/crypto/src/backend:openssl_backend_active": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    visibility = ["//score/crypto/src/backend/score_provider:__pkg__"],
    deps = [
        ":openssl_backend_adapter",
        ":openssl_backend_define",
    ],
)

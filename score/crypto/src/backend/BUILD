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

load("@bazel_skylib//rules:common_settings.bzl", "bool_flag")
load("@rules_cc//cc:defs.bzl", "cc_library")

# ============================================================================
# Enable / disable bool_flags
# ============================================================================

bool_flag(
    name = "score_crypto_pkcs11_enabled",
    build_setting_default = True,
    visibility = ["//visibility:public"],
)

bool_flag(
    name = "score_crypto_score_backend_enabled",
    build_setting_default = True,
    visibility = ["//visibility:public"],
)

bool_flag(
    name = "score_crypto_score_openssl_enabled",
    build_setting_default = True,
    visibility = ["//visibility:public"],
)

bool_flag(
    name = "score_crypto_score_primula_enabled",
    build_setting_default = False,
    visibility = ["//visibility:public"],
)

# ============================================================================
# config_settings — all check the POSITIVE (True) case
# ============================================================================

config_setting(
    name = "pkcs11_enabled",
    flag_values = {":score_crypto_pkcs11_enabled": "True"},
    visibility = ["//:__subpackages__"],
)

config_setting(
    name = "score_backend_enabled",
    flag_values = {":score_crypto_score_backend_enabled": "True"},
    visibility = ["//:__subpackages__"],
)

config_setting(
    name = "primula_enabled",
    flag_values = {":score_crypto_score_primula_enabled": "True"},
    visibility = ["//:__subpackages__"],
)

# True only when both the master score-backend gate and the OpenSSL sub-backend
# flag are enabled. Used in target_compatible_with so that disabling either flag
# excludes OpenSSL targets from wildcard builds.
config_setting(
    name = "openssl_backend_active",
    flag_values = {
        ":score_crypto_score_backend_enabled": "True",
        ":score_crypto_score_openssl_enabled": "True",
    },
    visibility = ["//:__subpackages__"],
)

# ============================================================================
# Score Provider Backends
# ============================================================================

# Master gate for the score-provider backend family.
# Each sub-backend manages its own enable/disable inside its package via a
# single-flag select(), so this target only checks the master flag.
# Heavy: adapter implementations are pulled in transitively.
# Only score_provider/backend (config parser) should consume this target.
cc_library(
    name = "active_score_backends",
    visibility = ["//:__subpackages__"],
    deps = select({
        ":score_backend_enabled": [
            "//score/crypto/src/backend/score_provider:all_score_backends",
            "//score/crypto/src/backend/score_provider:score_backend_headers",
        ],
        "//conditions:default": [],
    }),
)

# Lightweight: single define exposing whether the score provider backend family
# is compiled in. Used as implementation_deps where the define is needed without
# propagating the discovery header or adapter implementations.
cc_library(
    name = "score_backend_defines",
    defines = select({
        ":score_backend_enabled": ["SCORE_BACKEND_ENABLED=1"],
        "//conditions:default": [],
    }),
    visibility = ["//:__subpackages__"],
)

# ============================================================================
# PKCS#11 Backend
# ============================================================================

# Label flag allowing command-line override of the PKCS#11 implementation.
# Example override:
#   bazel build //score/crypto/src/daemon:crypto_daemon \
#       --//score/crypto/src/backend:pkcs11_backend=//external/vendor_hsm:backend
label_flag(
    name = "pkcs11_backend",
    build_setting_default = "//third_party/soft_hsm:softhsm_shared",
    visibility = ["//visibility:public"],
)

# Lightweight: single define exposing whether PKCS#11 is compiled in.
# Used as implementation_deps in targets that need the define for compilation
# but must not propagate it to their consumers.
cc_library(
    name = "pkcs11_backend_defines",
    defines = select({
        ":pkcs11_enabled": ["SCORE_CRYPTO_PKCS11_ENABLED=1"],
        "//conditions:default": [],
    }),
    visibility = ["//:__subpackages__"],
)

# PKCS#11 backend: selected library + fixed config parser.
# Only provider_pkcs11_factory should consume this (via implementation_deps).
cc_library(
    name = "active_pkcs11_backend",
    visibility = ["//:__subpackages__"],
    deps = select({
        ":pkcs11_enabled": [
            ":pkcs11_backend",
            "//score/crypto/src/backend/pkcs11:pkcs11_config_parser",
        ],
        "//conditions:default": [],
    }),
)

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

load("@bazel_skylib//rules:common_settings.bzl", "bool_flag", "string_flag")
load("@bazel_skylib//lib:selects.bzl", "selects")
load("@rules_cc//cc:defs.bzl", "cc_library")

# ============================================================================
# Enable / disable bool_flags
# ============================================================================

bool_flag(
    name = "score_crypto_pkcs11_backend_enabled",
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
    name = "score_crypto_score_pqc_provider_enabled",
    build_setting_default = False,
    visibility = ["//visibility:public"],
)

# ============================================================================
# config_settings — all check the POSITIVE (True) case
# ============================================================================

config_setting(
    name = "pkcs11_backend_enabled",
    flag_values = {":score_crypto_pkcs11_backend_enabled": "True"},
    visibility = ["//visibility:public"],
)

config_setting(
    name = "score_backend_enabled",
    flag_values = {":score_crypto_score_backend_enabled": "True"},
    visibility = ["//visibility:public"],
)

# True only when both the master score-backend gate and the score sub-backend
# flag are enabled. Used in target_compatible_with so that disabling either flag
# excludes sub-backend targets from wildcard builds.

config_setting(
    name = "pqc_provider_backend_active",
    flag_values = {
        ":score_crypto_score_backend_enabled": "True",
        ":score_crypto_score_pqc_provider_enabled": "True",
    },
    visibility = ["//:__subpackages__"],
)

config_setting(
    name = "openssl_backend_active",
    flag_values = {
        ":score_crypto_score_backend_enabled": "True",
        ":score_crypto_score_openssl_enabled": "True",
    },
    # Public: the integration test selects on this, and py_itf_test does not
    # accept a package-scoped config_setting as a select key.
    visibility = ["//visibility:public"],
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
        ":score_backend_enabled": ["SCORE_CRYPTO_SCORE_BACKEND_ENABLED=1"],
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
    build_setting_default = "//third_party/soft_hsm:soft_hsm",
    visibility = ["//visibility:public"],
)

# Label flag allowing command-line override of the shared PKCS#11 implementation
# when dynamic linking is enabled (--//score/crypto/src/backend:pkcs11_link_type=dynamic).
# Default is SoftHSM's shared library target.
label_flag(
    name = "pkcs11_shared_backend",
    build_setting_default = "//third_party/soft_hsm:softhsm_shared",
    visibility = ["//visibility:public"],
)

# Command line flag allowing users to select PKCS#11 link type independently.
# Usage:
#   bazel build //score/crypto/src/daemon:crypto_daemon \
#       --//score/crypto/src/backend:pkcs11_link_type=dynamic
string_flag(
    name = "pkcs11_link_type",
    build_setting_default = "static",
    values = [
        "static",
        "dynamic",
    ],
    visibility = ["//visibility:public"],
)

config_setting(
    name = "pkcs11_link_dynamic",
    flag_values = {":pkcs11_link_type": "dynamic"},
    visibility = ["//visibility:public"],
)

# Dynamic PKCS#11 is added to the daemon if:
# 1. PKCS#11 link type is dynamic, AND
# 2. PKCS#11 backend is enabled.
selects.config_setting_group(
    name = "dynamic_pkcs11_in_daemon",
    match_all = [
        ":pkcs11_link_dynamic",
        ":pkcs11_backend_enabled",
    ],
    visibility = ["//visibility:public"],
)

# Dynamic OpenSSL Case A: User explicitly passed --@score_openssl//:use_dynamic_openssl=true
# AND OpenSSL backend is active in the daemon.
selects.config_setting_group(
    name = "dynamic_openssl_via_flag",
    match_all = [
        "@score_openssl//:dynamic_openssl_enabled",
        ":openssl_backend_active",
    ],
    visibility = ["//visibility:public"],
)

# Dynamic OpenSSL Case B (Guardrail):
# Dynamic PKCS#11 is active AND OpenSSL backend is active in the daemon.
# (Prevents two static OpenSSL instances in memory).
selects.config_setting_group(
    name = "dynamic_openssl_forced_by_pkcs11",
    match_all = [
        ":pkcs11_link_dynamic",
        ":openssl_backend_active",
    ],
    visibility = ["//visibility:public"],
)

# Master switch: OpenSSL shared is linked into the daemon if EITHER Case A OR Case B is true.
selects.config_setting_group(
    name = "dynamic_openssl_in_daemon",
    match_any = [
        ":dynamic_openssl_via_flag",
        ":dynamic_openssl_forced_by_pkcs11",
    ],
    visibility = ["//visibility:public"],
)

# Lightweight: single define exposing whether PKCS#11 is compiled in.
# Used as implementation_deps in targets that need the define for compilation
# but must not propagate it to their consumers.
cc_library(
    name = "pkcs11_backend_defines",
    defines = select({
        ":pkcs11_backend_enabled": ["SCORE_CRYPTO_PKCS11_BACKEND_ENABLED=1"],
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
        ":pkcs11_backend_enabled": [
            ":pkcs11_backend",
            "//score/crypto/src/backend/pkcs11:pkcs11_config_parser",
        ],
        "//conditions:default": [],
    }),
)

# ============================================================================
# Cryptoki Provider Selection
# ============================================================================

config_setting(
    name = "rust_cryptoki_static_selected",
    flag_values = {
        ":pkcs11_backend": "//score/cryptoki:cryptoki_static_wrapped",
    },
)

config_setting(
    name = "rust_cryptoki_dynamic_selected",
    flag_values = {
        ":pkcs11_backend": "//score/cryptoki:cryptoki_cdylib_wrapped",
    },
)

selects.config_setting_group(
    name = "rust_cryptoki_selected",
    match_any = [
        ":rust_cryptoki_static_selected",
        ":rust_cryptoki_dynamic_selected",
    ],
    visibility = ["//visibility:public"],
)

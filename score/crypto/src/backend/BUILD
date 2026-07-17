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
load(
    ":backend_exports.bzl",
    "BACKEND_DEFINES",
    "ENABLE_PKCS11_BACKEND",
    "PKCS11_BACKEND_DEFAULT_LABEL",
    "PKCS11_BACKEND_DEPS",
    "SCORE_BACKEND_DEPS",
)

# ============================================================================
# Backend Architecture:
# ============================================================================
#
# MASTER CONFIGURATION: All backend selection flags are in backend_exports.bzl
#
# PKCS#11 Backend:
#   - Enable/disable: Set ENABLE_PKCS11_BACKEND in backend_exports.bzl
#   - Implementation selection: Set PKCS11_BACKEND = "softhsm" | "vendor_hsm" | ...
#
# Score Provider Backends (multiple can be active simultaneously):
#   - openssl/  : OpenSSL crypto backend
#   - primula/  : Primula backend (future)
#   Enable/disable by setting ENABLE_BACKEND_OPENSSL, etc. in backend_exports.bzl
#
# See backend_exports.bzl for the single source of truth for all backend flags.
# ============================================================================
#

# ============================================================================
# Score Provider Backends
# ============================================================================
#

# Heavy: actual adapter implementations.
# Only score_provider_factory should consume this (via implementation_deps).
cc_library(
    name = "active_score_backends",
    visibility = ["//visibility:public"],
    deps = [
        "//score/crypto/src/backend/score_provider:score_backend_defines",
    ] + SCORE_BACKEND_DEPS,
)

# ============================================================================
# PKCS#11 Backend
# ============================================================================
#

# Label flag allowing command-line override of the PKCS#11 backend.
# Default value is derived from PKCS11_BACKEND in backend_exports.bzl.
# Example override:
#   bazel build //score/crypto/src/daemon:crypto_daemon \
#       --//score/crypto/src/backend:pkcs11_backend=//external/vendor_hsm:backend
label_flag(
    name = "pkcs11_backend",
    build_setting_default = PKCS11_BACKEND_DEFAULT_LABEL,
)

# Lightweight: single define exposing whether PKCS#11 is compiled in.
# Replaces the __has_include anti-pattern in provider_manager_factory.
cc_library(
    name = "pkcs11_backend_defines",
    defines = (["SCORE_CRYPTO_PKCS11_ENABLED=1"] if ENABLE_PKCS11_BACKEND else []),
    visibility = ["//visibility:public"],
)

# PKCS#11 backend: selected library + fixed config parser.
# Only provider_pkcs11_library/factory should consume this (via implementation_deps).
cc_library(
    name = "active_pkcs11_backend",
    visibility = ["//visibility:public"],
    deps = [
        ":pkcs11_backend_defines",
    ] + ([
        ":pkcs11_backend",
        "//score/crypto/src/backend/pkcs11:pkcs11_config_parser",
    ] if ENABLE_PKCS11_BACKEND else []),
)

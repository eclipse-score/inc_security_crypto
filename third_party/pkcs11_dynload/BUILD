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
load("//third_party/pkcs11_dynload:provider.bzl", "pkcs11_header_provider")

# Provides the PKCS#11 header via the generic provider abstraction.
# Supports multiple backends (e.g., SoftHSM, Cryptoki, HSE) without hard‑coding one.
# Builds the PKCS#11 dynloader that loads the active module at runtime.
# The selected header provider is controlled by the pkcs11_header_source setting.
# This file contains only the dynloader and provider wiring, not backend logic.

# ------------------------------------------------------------------------------
# Extract pkcs11.h from the SoftHSM source tree.
# This produces include/pkcs11.h in the normalized layout expected by all
# PKCS#11 header providers.
# ------------------------------------------------------------------------------
genrule(
    name = "extract_pkcs11_headers",
    srcs = ["@softhsm_source//:all"],
    outs = ["include/pkcs11.h"],
    cmd = """
        mkdir -p $(RULEDIR)/include
        # Find the pkcs11.h file inside the SoftHSM source tree
        for f in $(locations @softhsm_source//:all); do
            case "$$f" in
                */src/lib/pkcs11/pkcs11.h)
                    cp "$$f" "$(RULEDIR)/include/pkcs11.h"
                    exit 0
                    ;;
            esac
        done
        echo "ERROR: pkcs11.h not found in SoftHSM source" >&2
        exit 1
    """,
    visibility = ["//visibility:private"],
)

# ------------------------------------------------------------------------------
# Build setting selecting which PKCS#11 header provider to use.
# Default = SoftHSM. Other providers (e.g., HSE) may override this.
#
# Example override for an assumed header provider pkcs11_hse:
#   bazel build //third_party/pkcs11_dynload:pkcs11_dynload_shared \
#       --//third_party/pkcs11_dynload:pkcs11_header_source=//third_party/pkcs11_hse:pkcs11_hse_header
# ------------------------------------------------------------------------------
label_flag(
    name = "pkcs11_header_source",
    build_setting_default = "//third_party/pkcs11_dynload:soft_hsm_header",
    visibility = ["//visibility:public"],
)

# ------------------------------------------------------------------------------
# SoftHSM implementation of the PKCS#11 header provider abstraction.
# Other providers (e.g., HSE) implement the same interface in their own BUILD.
# ------------------------------------------------------------------------------
pkcs11_header_provider(
    name = "soft_hsm_header",
    hdrs = [":extract_pkcs11_headers"],
)

# ------------------------------------------------------------------------------
# Dynload includes: consume ONLY the selected PKCS#11 header provider.
# This keeps dynload fully decoupled from specific PKCS#11 backends.
# ------------------------------------------------------------------------------
cc_library(
    name = "pkcs11_dynload_includes",
    visibility = ["//visibility:public"],
    deps = [
        ":pkcs11_header_source",
    ],
)

# ------------------------------------------------------------------------------
# PKCS#11 dynloader implementation.
#
# This library loads a PKCS#11 module at runtime via dlopen(). The path to the
# module is provided through the preprocessor macro PKCS11_LIB, which *must* be
# defined by the build caller (e.g. via --copt=-DPKCS11_LIB=/usr/lib/softhsm/libsofthsm2.so).
# -----------------------------------------------------------------------------
cc_library(
    name = "pkcs11_dynload_shared",
    srcs = ["pkcs11_dynload.cpp"],
    includes = ["."],
    linkstatic = False,
    visibility = ["//visibility:public"],
    deps = [
        ":pkcs11_dynload_includes",
        "@score_baselibs//score/mw/log",
    ],
)

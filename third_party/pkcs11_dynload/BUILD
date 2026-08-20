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

# Provides the PKCS#11 header via the generic provider abstraction.
# Supports multiple backends without hard‑coding one.
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

cc_library(
    name = "soft_hsm_header",
    hdrs = [":extract_pkcs11_headers"],
    includes = ["include"],
    visibility = ["//visibility:private"],
)

# ------------------------------------------------------------------------------
# Build setting selecting which PKCS#11 header provider to use.
# Default = SoftHSM. Other providers may override this.
# ------------------------------------------------------------------------------

label_flag(
    name = "pkcs11_header_source",
    build_setting_default = "//third_party/pkcs11_dynload:soft_hsm_header",
    visibility = ["//visibility:public"],
)

# ------------------------------------------------------------------------------
# PKCS#11 dynloader implementation.
#
# This library loads a PKCS#11 module at runtime via dlopen(). The absolute
# module path is provided via the Bazel build setting `--define pkcs11_lib=...`
# and written into the generated header `pkcs11_lib_path.h`. This avoids fragile
# preprocessor string escaping. The build fails if `pkcs11_lib` is not defined.
#
# On Linux, dlopen/dlsym require linking against libdl. On QNX, libdl is part
# of libc and must not be linked explicitly.
# ------------------------------------------------------------------------------

genrule(
    name = "pkcs11_lib_path",
    outs = ["include/pkcs11_lib_path.h"],
    cmd = """
        if [ -z "$(pkcs11_lib)" ]; then \
            echo "ERROR: pkcs11_lib not set" >&2; \
            exit 1; \
        fi
        echo '#pragma once' > $@
        echo 'static const char* kPkcs11LibPath = "$(pkcs11_lib)";' >> $@
    """,
)

cc_library(
    name = "pkcs11_dynload_shared",
    srcs = ["pkcs11_dynload.cpp"],
    hdrs = [":pkcs11_lib_path"],
    includes = ["include"],
    linkopts = select({
        "//platforms:is_qnx_aarch64": [],
        "//platforms:is_qnx_x86_64": [],
        "//conditions:default": ["-ldl"],
    }),
    linkstatic = False,
    visibility = ["//visibility:public"],
    deps = [
        ":pkcs11_header_source",
        "@score_baselibs//score/mw/log",
    ],
)

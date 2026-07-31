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

# Default Pkcs11Config::ParseConfig(config) implementation.
#
# This is a fixed dependency of active_pkcs11_backend and is always present
# when PKCS#11 is enabled, regardless of which backend library is selected via
# the pkcs11_backend label_flag.
#
# Currently hardwires SoftHSM token defaults. Future: wire actual flatbuffer
# config parsing here without touching backend library targets.
#
# Backend subdirectories (softhsm/, vendor_hsm/, etc.) provide only the
# PKCS#11 library and headers — they do NOT own config parsing.
#
# To add a new PKCS#11 backend library:
#   1. Add entry to pkcs11_backend_label() in backend/backend_config.bzl pointing
#      to the library target (third_party or external)
#   2. Set PKCS11_BACKEND = "<name>" in backend/backend_exports.bzl
#   Or override at build time:
#     --//score/crypto/src/backend:pkcs11_backend=//third_party/your_hsm:your_hsm
cc_library(
    name = "pkcs11_config_parser",
    srcs = ["pkcs11_token_config_parser.cpp"],
    visibility = ["//score/crypto/src/backend:__pkg__"],
    deps = [
        "//score/crypto/src/daemon/provider/pkcs11:pkcs11_token_config",
    ],
)

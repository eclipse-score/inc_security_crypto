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

load("@rules_cc//cc:cc_library.bzl", "cc_library")

# Header-only: interfaces + shared path validation utility.
# No format-specific deps — adding a new format (json, flatbuffer, ...) only
# requires adding a new cc_library target in this file; nothing else changes.
cc_library(
    name = "deployment_iface",
    hdrs = [
        "deployment_path_utils.hpp",
        "i_deployment_loader.hpp",
        "i_deployment_writer.hpp",
    ],
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/common:common_types",
        "//score/crypto/daemon/common",
        "//score/crypto/daemon/key_management:key_management_headers",
    ],
)

# KV format implementation.  Stdlib-only — no extra library deps required.
# To add a new format, create an analogous target here (e.g. json_deployment)
# and add it as a dep to //score/crypto/daemon/key_management:key_management.
cc_library(
    name = "kv_deployment",
    srcs = [
        "kv/kv_deployment_loader.cpp",
        "kv/kv_deployment_writer.cpp",
    ],
    hdrs = [
        "kv/kv_deployment_loader.hpp",
        "kv/kv_deployment_writer.hpp",
    ],
    visibility = ["//:__subpackages__"],
    deps = [":deployment_iface"],
)

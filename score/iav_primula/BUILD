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

load("@rules_rust//rust:defs.bzl", "rust_library", "rust_static_library")

rust_library(
    name = "iav_primula",
    srcs = [
        "src/ffi.rs",
    ],
    crate_name = "iav_primula",
    crate_root = "src/ffi.rs",
    edition = "2021",
    visibility = ["//visibility:public"],
)

rust_static_library(
    name = "iav_primula_staticlib",
    srcs = [
        "src/ffi.rs",
    ],
    crate_name = "iav_primula",
    crate_root = "src/ffi.rs",
    edition = "2021",
    visibility = ["//visibility:public"],
)

cc_library(
    name = "iav_primula_ffi_headers",
    hdrs = ["include/iav_primula_ffi.h"],
    visibility = ["//visibility:public"],
)

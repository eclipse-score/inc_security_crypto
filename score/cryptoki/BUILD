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

load("@rules_rust//rust:defs.bzl", "rust_library", "rust_shared_library")


filegroup(
    name = "src",
    srcs = glob(["**/*.rs"]) + [
        "Cargo.lock",
        "Cargo.toml",
    ],
)

DEPS = [
    # --- Company Approved (Score Ecosystem) ---
    "@score_crates//:libc",
    "@score_crates//:serde",
    "@score_crates//:serde_json",
    "@score_baselibs_rust//src/log/score_log",
    "@score_logging//score/mw/log/rust/score_log_bridge",

    # --- Community Fallback (Crate Universe) ---
    "@crates//:argon2",
    "@crates//:dirs",
    "@crates//:once_cell",
    "@crates//:parking_lot",
    "@crates//:parsec-client",
    "@crates//:tempfile",
    "@crates//:toml",
    "@crates//:zeroize",
    "@crates//:openssl",
    "//third_party/openssl:openssl_shared",
]

# Shared C/C++ linker flags required by score_log_bridge
CPP_LINKER_FLAGS = select({
    "@platforms//os:qnx": ["-Clink-arg=-lc++"],   # QNX uses libc++
    "//conditions:default": ["-Clink-arg=-lstdc++"],
}) + [
    "-Clink-arg=-lm",
    "-Clink-arg=-lc",
]

rust_library(
    name = "cryptoki_lib",
    srcs = glob(["**/*.rs"]),
    crate_name = "cryptoki",
    crate_root = "lib.rs",
    rustc_flags = CPP_LINKER_FLAGS,
    visibility = ["//visibility:public"],
    deps = DEPS,
)

rust_shared_library(
    name = "cryptoki_cdylib",
    srcs = glob(["**/*.rs"]),
    crate_name = "cryptoki",
    crate_root = "lib.rs",
    rustc_flags = CPP_LINKER_FLAGS,
    visibility = ["//visibility:public"],
    deps = DEPS,
)

cc_library(
    name = "cryptoki_cdylib_wrapped",
    hdrs = [
        "cpp/pkcs11.h",
        "cpp/pkcs11_cpp.hpp",
    ],
    includes = ["cpp"],
    linkstatic = False,
    visibility = ["//visibility:public"],
    deps = [
        ":cryptoki_cdylib",
    ],
)

cc_library(
    name = "cryptoki_headers",
    hdrs = [
        "cpp/pkcs11.h",
        "cpp/pkcs11_cpp.hpp",
    ],
    includes = ["cpp"],
    visibility = ["//visibility:public"],
)

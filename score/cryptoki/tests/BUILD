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

load("@crates//:defs.bzl", "aliases", "all_crate_deps")
load("@rules_rust//rust:defs.bzl", "rust_test")


filegroup(
    name = "rust_test_sources",
    srcs = glob(["**/*.rs"]),
)

_COMMON_DEPS = [
    "//score/cryptoki:cryptoki_lib",
    "//third_party/openssl:openssl_shared",
]

_TESTS_WITH_COMMON = [
    "always_authenticate",
    "attribute_policy",
    "copy_object",
    "lifecycle",
    "mechanism_policy",
    "message_api",
    "persistence_integration",
    "pkcs11_integration",
    "pkcs11_v3_integration",
    "profile_objects",
    "ro_session",
    "session_vs_token_objects",
    "token_info",
    "wrap_acl",
]

_TESTS_NO_COMMON = [
    "connect_disconnect",
    "encryption",
    "engine_integration",
    "hashing",
    "misc",
    "object_management",
    "signing",
    "slots_and_tokens",
    "storage_atomic_writes",
]

_CPP_LINKER_FLAGS = [
    "-Clink-arg=-lstdc++",
    "-Clink-arg=-lm",
    "-Clink-arg=-lc",
    "-Clink-arg=-lssl",
    "-Clink-arg=-lcrypto",
]

[rust_test(
    name = name,
    srcs = [
        name + ".rs",
        "common/mod.rs",
    ],
    aliases = aliases(
        package_name = "score/cryptoki",
        normal_dev = True,
        proc_macro_dev = True,
    ),
    crate_root = name + ".rs",
    env = {"RUST_TEST_THREADS": "1"},
    rustc_flags = _CPP_LINKER_FLAGS,
    visibility = ["//visibility:public"],
    proc_macro_deps = all_crate_deps(
        package_name = "score/cryptoki",
        proc_macro_dev = True,
    ),
    deps = _COMMON_DEPS + all_crate_deps(
        package_name = "score/cryptoki",
        normal = True,
    ) + all_crate_deps(
        package_name = "score/cryptoki",
        normal_dev = True,
    ),
) for name in _TESTS_WITH_COMMON]

[rust_test(
    name = name,
    srcs = [name + ".rs"],
    aliases = aliases(
        package_name = "score/cryptoki",
        normal_dev = True,
        proc_macro_dev = True,
    ),
    crate_root = name + ".rs",
    env = {"RUST_TEST_THREADS": "1"},
    rustc_flags = _CPP_LINKER_FLAGS,
    visibility = ["//visibility:public"],
    proc_macro_deps = all_crate_deps(
        package_name = "score/cryptoki",
        proc_macro_dev = True,
    ),
    deps = _COMMON_DEPS + all_crate_deps(
        package_name = "score/cryptoki",
        normal = True,
    ) + all_crate_deps(
        package_name = "score/cryptoki",
        normal_dev = True,
    ),
) for name in _TESTS_NO_COMMON]

test_suite(
    name = "integration_tests",
    tests = [":" + name for name in _TESTS_WITH_COMMON + _TESTS_NO_COMMON],
)

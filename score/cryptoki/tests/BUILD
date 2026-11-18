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

load("@rules_rust//rust:defs.bzl", "rust_test")

filegroup(
    name = "rust_test_sources",
    srcs = glob(["**/*.rs"]),
)

_COMMON_DEPS = [
    "//score/cryptoki:cryptoki_lib",
    "@score_crates//:libc",
    "@score_crates//:serde_json",
    "@score_crates//:serial_test",
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

# TODO(#workaround): Mark flaky tests to be retried or handled specially
_FLAKY_TESTS = [
    "attribute_policy",
    "copy_object",
    "engine_integration",
    "mechanism_policy",
    "message_api",
    "ro_session",
    "signing",
    "pkcs11_integration",
    "wrap_acl",
]

_CPP_LINKER_FLAGS = select({
    "@platforms//os:qnx": ["-Clink-arg=-lc++"],  # QNX uses libc++
    "//conditions:default": ["-Clink-arg=-lstdc++"],
}) + [
    "-Clink-arg=-lm",
    "-Clink-arg=-lc",
]

[rust_test(
    name = name,
    srcs = [
        name + ".rs",
        "common/mod.rs",
    ],
    crate_root = name + ".rs",
    env = {"RUST_TEST_THREADS": "1"},
    flaky = name in _FLAKY_TESTS,
    rustc_flags = _CPP_LINKER_FLAGS,
    tags = ["flaky"] if name in _FLAKY_TESTS else [],
    visibility = ["//visibility:public"],
    deps = _COMMON_DEPS,
) for name in _TESTS_WITH_COMMON]

[rust_test(
    name = name,
    srcs = [name + ".rs"],
    crate_root = name + ".rs",
    env = {"RUST_TEST_THREADS": "1"},
    flaky = name in _FLAKY_TESTS,
    rustc_flags = _CPP_LINKER_FLAGS,
    tags = ["flaky"] if name in _FLAKY_TESTS else [],
    visibility = ["//visibility:public"],
    deps = _COMMON_DEPS,
) for name in _TESTS_NO_COMMON]

test_suite(
    name = "integration_tests",
    tests = [":" + name for name in _TESTS_WITH_COMMON + _TESTS_NO_COMMON],
)

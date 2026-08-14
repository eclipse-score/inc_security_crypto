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

load("@rules_cc//cc:defs.bzl", "cc_binary")
load("//score/tests/bazel:integration.bzl", "integration_test")

cc_binary(
    name = "init_pkcs11_token",
    srcs = ["init_pkcs11_token.cpp"],
    deps = [
        "//score/crypto/src/backend:active_pkcs11_backend",
    ],
)

cc_binary(
    name = "score_api_hash_example",
    srcs = ["score_api_hash_example.cpp"],
    data = [
        "//score/tests/test_vectors/config:integration_test_config",
        "//score/tests/test_vectors/hash:hash_test_vectors",
    ],
    dynamic_deps = ["//third_party/grpc:libgrpc_shared"],
    deps = [
        "//score/crypto/src/api:crypto_stack",
        "//score/tests/utility",
        "@googletest//:gtest",
    ],
)

cc_binary(
    name = "score_api_mac_example",
    srcs = ["score_api_mac_example.cpp"],
    data = [
        "//score/tests/test_vectors/config:integration_test_config",
        "//score/tests/test_vectors/mac:mac_test_vectors",
    ],
    dynamic_deps = ["//third_party/grpc:libgrpc_shared"],
    deps = [
        "//score/crypto/src/api:crypto_stack",
        "//score/tests/utility",
        "@googletest//:gtest",
    ],
)

cc_binary(
    name = "hash_performance_test",
    srcs = ["hash_performance_test.cpp"],
    data = ["//score/tests/test_vectors/hash:hash_test_vectors"],
    dynamic_deps = ["//third_party/grpc:libgrpc_shared"],
    deps = [
        "//score/crypto/src/api:crypto_stack",
        "//score/tests/utility",
        "@googletest//:gtest",
    ],
)

cc_binary(
    name = "score_demo",
    srcs = ["score_demo.cpp"],
    data = [
        "//score/tests/test_vectors/config:integration_test_config",
        "//score/tests/test_vectors/mac:mac_test_vectors",
    ],
    dynamic_deps = ["//third_party/grpc:libgrpc_shared"],
    deps = [
        "//score/crypto/src/api:crypto_stack",
        "//score/tests/utility",
    ],
)

integration_test(
    name = "integration_test",
    size = "small",
    srcs = ["integration_test.py"],
    binaries = [
        ":init_pkcs11_token",
        ":score_api_hash_example",
        ":score_api_mac_example",
        ":hash_performance_test",
        ":score_demo",
        "//score/crypto/src/daemon:crypto_daemon",
    ],
    configs = [
        "//score/tests/config:logging.json",
        "//score/tests/test_vectors/config:integration_test_config",
    ],
    file_pkgs = [
        "//score/tests/test_vectors/hash:hash_test_vectors_pkg",
        "//score/tests/test_vectors/mac:mac_test_vectors_pkg",
    ],
    libraries = [
        "//score/crypto/src/api/control_plane",
        "//third_party/grpc:libgrpc_shared",
        "//third_party/openssl:openssl_so",
        "//third_party/soft_hsm:softhsm_so",
    ],
    deps = [
        "//score/tests:common_fixtures",
        "//score/tests/utility/process_runner",
    ],
)

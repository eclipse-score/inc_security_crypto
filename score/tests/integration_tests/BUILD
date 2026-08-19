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
    target_compatible_with = select({
        "//score/crypto/src/backend:pkcs11_backend_enabled": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    deps = [
        "//score/crypto/src/backend:active_pkcs11_backend",
    ],
)

cc_binary(
    name = "score_api_hash_test",
    srcs = ["score_api_hash_test.cpp"],
    data = [
        "//score/tests/test_vectors/config:integration_test_config",
        "//score/tests/test_vectors/hash:hash_test_vectors",
    ],
    defines = select({
        "//score/crypto/src/backend:pkcs11_backend_enabled": ["SCORE_CRYPTO_HARDWARE_BACKEND_ENABLED=1"],
        "//conditions:default": [],
    }) + select({
        "//score/crypto/src/backend:openssl_backend_active": ["SCORE_CRYPTO_SOFTWARE_BACKEND_ENABLED=1"],
        "//conditions:default": [],
    }),
    dynamic_deps = ["//third_party/grpc:libgrpc_shared"],
    deps = [
        "//score/crypto/src/api:crypto_stack",
        "//score/tests/utility",
        "@googletest//:gtest",
    ],
)

cc_binary(
    name = "score_api_mac_test",
    srcs = ["score_api_mac_test.cpp"],
    data = [
        "//score/tests/test_vectors/config:integration_test_config",
        "//score/tests/test_vectors/mac:mac_test_vectors",
    ],
    defines = select({
        "//score/crypto/src/backend:pkcs11_backend_enabled": ["SCORE_CRYPTO_HARDWARE_BACKEND_ENABLED=1"],
        "//conditions:default": [],
    }) + select({
        "//score/crypto/src/backend:openssl_backend_active": ["SCORE_CRYPTO_SOFTWARE_BACKEND_ENABLED=1"],
        "//conditions:default": [],
    }),
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
    defines = select({
        "//score/crypto/src/backend:pkcs11_backend_enabled": ["SCORE_CRYPTO_HARDWARE_BACKEND_ENABLED=1"],
        "//conditions:default": [],
    }) + select({
        "//score/crypto/src/backend:openssl_backend_active": ["SCORE_CRYPTO_SOFTWARE_BACKEND_ENABLED=1"],
        "//conditions:default": [],
    }),
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
        ":score_api_hash_test",
        ":score_api_mac_test",
        ":hash_performance_test",
        ":score_demo",
        "//score/crypto/src/daemon:crypto_daemon",
    ] + select({
        "//score/crypto/src/backend:pkcs11_backend_enabled": [":init_pkcs11_token"],
        "//conditions:default": [],
    }),
    configs = [
        "//score/tests/config:logging.json",
        "//score/tests/test_vectors/config:integration_test_config",
    ],
    extra_args = select({
        "//score/crypto/src/backend:pkcs11_backend_enabled": ["--pkcs11-backend-enabled"],
        "//conditions:default": [],
    }),
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

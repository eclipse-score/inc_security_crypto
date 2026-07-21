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

load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_test")
load("@score_itf//:defs.bzl", "py_itf_test")

cc_binary(
    name = "control_client_app",
    srcs = ["control_client_app.cpp"],
    dynamic_deps = ["//third_party/grpc:libgrpc_shared"],
    deps = [
        "//score/crypto/api:operations",
        "//score/crypto/api/control_plane:control_plane_impl",
        "@googletest//:gtest",
    ],
)

cc_binary(
    name = "init_softhsm_token",
    srcs = ["init_softhsm_token.cpp"],
    deps = [
        "//third_party/soft_hsm:libsofthsm_shared",
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
        "//score/crypto/api:crypto_stack",
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
        "//score/crypto/api:crypto_stack",
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
        "//score/crypto/api:crypto_stack",
        "//score/tests/utility",
    ],
)

py_itf_test(
    name = "integration_test_docker",
    size = "small",
    srcs = ["integration_test.py"],
    args = [
        "--docker-image=ubuntu:24.04",
        "--log-level=WARNING",
    ],
    data = [
        ":control_client_app",
        ":init_softhsm_token",
        ":score_api_hash_example",
        ":score_api_mac_example",
        ":score_demo",
        "//score/crypto/api/control_plane",
        "//score/crypto/daemon:crypto_daemon",
        "//score/tests/config:logging.json",
        "//third_party/grpc:libgrpc_shared",
        "//third_party/openssl:openssl_shared",
        "//third_party/soft_hsm:soft_hsm_cmake",
    ],
    plugins = [
        "itf.plugins.docker",
    ],
)

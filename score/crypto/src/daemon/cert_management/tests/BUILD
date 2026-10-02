# *******************************************************************************
# Copyright (c) 2026 Contributors to the Eclipse Foundation
# SPDX-License-Identifier: Apache-2.0
# *******************************************************************************

load("@rules_cc//cc:cc_test.bzl", "cc_test")

cc_library(
    name = "test_environment",
    testonly = True,
    hdrs = ["test_environment.hpp"],
    visibility = ["//score/crypto/src/daemon/cert_management:__pkg__"],
)

cc_test(
    name = "test_file_backed_slot_handler",
    srcs = [
        "slot/file_backed_slot_handler_test.cpp",
        "test_environment.hpp",
    ],
    data = [
        "//score/tests/test_vectors/certificate:certificate_test_vectors",
    ],
    target_compatible_with = select({
        "//score/crypto/src/backend:openssl_backend_active": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    deps = [
        "//score/crypto/src/daemon/cert_management",
        "//score/crypto/src/daemon/cert_management:cert_management_headers",
        "//score/crypto/src/daemon/cert_management:cert_management_internal_headers",
        "//score/crypto/src/daemon/common/storage:kv_deployment",
        "//score/crypto/src/daemon/provider/score_provider/openssl:openssl_cert_management_headers",
        "//score/crypto/src/daemon/provider/score_provider/openssl:openssl_cert_parser_library",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "test_trust_store_manager",
    srcs = [
        "test_environment.hpp",
        "truststore/test_trust_store_manager.cpp",
    ],
    data = [
        "//score/tests/test_vectors/certificate:certificate_test_vectors",
    ],
    target_compatible_with = select({
        "//score/crypto/src/backend:openssl_backend_active": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    deps = [
        "//score/crypto/src/daemon/cert_management",
        "//score/crypto/src/daemon/cert_management:cert_management_headers",
        "//score/crypto/src/daemon/cert_management:cert_management_internal_headers",
        "//score/crypto/src/daemon/cert_management:cert_management_runtime_headers",
        "//score/crypto/src/daemon/common/storage:kv_deployment",
        "//score/crypto/src/daemon/provider/score_provider/openssl:openssl_cert_management_headers",
        "//score/crypto/src/daemon/provider/score_provider/openssl:openssl_cert_parser_library",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "test_cert_management_service",
    srcs = [
        "service/test_cert_management_service.cpp",
        "test_environment.hpp",
    ],
    data = [
        "//score/tests/config:logging.json",
        "//score/tests/test_vectors/certificate:certificate_test_vectors",
    ],
    target_compatible_with = select({
        "//score/crypto/src/backend:openssl_backend_active": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    deps = [
        "//score/crypto/src/daemon/cert_management",
        "//score/crypto/src/daemon/cert_management:cert_management_daemon_headers",
        "//score/crypto/src/daemon/cert_management:cert_management_headers",
        "//score/crypto/src/daemon/cert_management:cert_management_internal_headers",
        "//score/crypto/src/daemon/cert_management:cert_management_runtime_headers",
        "//score/crypto/src/daemon/common/storage:kv_deployment",
        "//score/crypto/src/daemon/data_manager",
        "//score/crypto/src/daemon/provider/score_provider/openssl:openssl_cert_management_headers",
        "//score/crypto/src/daemon/provider/score_provider/openssl:openssl_cert_parser_library",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "test_certificate_management_integration",
    srcs = [
        "integration/test_certificate_management_integration.cpp",
        "test_environment.hpp",
    ],
    data = [
        "//score/tests/test_vectors/certificate:certificate_test_vectors",
    ],
    target_compatible_with = select({
        "//score/crypto/src/backend:openssl_backend_active": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    deps = [
        "//score/crypto/src/daemon/cert_management",
        "//score/crypto/src/daemon/cert_management:cert_management_headers",
        "//score/crypto/src/daemon/cert_management:cert_management_internal_headers",
        "//score/crypto/src/daemon/cert_management:cert_management_runtime_headers",
        "//score/crypto/src/daemon/cert_management:cert_management_slot_backend_headers",
        "//score/crypto/src/daemon/common/storage:kv_deployment",
        "//score/crypto/src/daemon/provider/score_provider/openssl:openssl_cert_management_headers",
        "//score/crypto/src/daemon/provider/score_provider/openssl:openssl_cert_parser_library",
        "@googletest//:gtest_main",
    ],
)

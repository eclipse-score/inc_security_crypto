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

load("@rules_cc//cc:defs.bzl", "cc_test")

# Tests the full config-to-registry pipeline for certificate management:
#   binary FlatBuffer → FlatBufferConfigParser → CertificateConfig
#         → ConfigDrivenSlotCatalog → CertSlotRegistry
#         → ConfigDrivenTrustStoreCatalog → TrustStoreManager
#
# Mirrors score/crypto/tests/key_management/test_key_config_manager.cpp.
cc_test(
    name = "test_cert_config_manager",
    srcs = ["test_cert_config_manager.cpp"],
    data = [
        "//score/crypto/tests/cert_management/config:cert_management_test_config",
    ],
    deps = [
        "//score/crypto/src/daemon/cert_management:cert_management",
        "//score/crypto/src/daemon/cert_management:cert_management_internal_headers",
        "//score/crypto/src/daemon/cert_management:cert_management_runtime_headers",
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/config:config_types",
        "//score/crypto/src/daemon/config:flatbuffer_config_parser",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "test_cert_module_startup",
    srcs = ["test_cert_module_startup.cpp"],
    data = [
        "//score/crypto/tests/cert_management/config:cert_module_startup_config",
    ],
    target_compatible_with = select({
        "//score/crypto/src/backend:openssl_backend_active": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    deps = [
        "//score/crypto/src/daemon/cert_management:cert_management",
        "//score/crypto/src/daemon/cert_management:cert_management_daemon_headers",
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/config:config_types",
        "//score/crypto/src/daemon/config:flatbuffer_config_parser",
        "//score/crypto/src/daemon/provider:provider_manager",
        "//score/crypto/src/daemon/provider/score_provider/openssl:provider_openssl_headers",
        "//score/crypto/src/daemon/provider/score_provider/openssl:provider_openssl_library",
        "@googletest//:gtest_main",
    ],
)

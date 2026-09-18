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
        "//score/crypto/src/daemon/cert_management:cert_management_headers",
        "//score/crypto/src/daemon/config:config_types",
        "//score/crypto/src/daemon/config:flatbuffer_config_parser",
        "@googletest//:gtest_main",
    ],
)

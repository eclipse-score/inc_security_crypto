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

load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")

cc_library(
    name = "csr_request_types",
    hdrs = ["csr_request.hpp"],
    visibility = ["//visibility:public"],
    deps = [
        "//score/crypto/src/api/common:crypto_common",
        "@score_baselibs//score/language/futurecpp",
        "@score_baselibs//score/result",
    ],
)

cc_library(
    name = "csr_template_types",
    hdrs = ["csr_template.hpp"],
    visibility = ["//visibility:public"],
    deps = [
        ":csr_request_types",
        "//score/crypto/src/api/certificate:csr_export",
        "//score/crypto/src/api/config:context_configs",
    ],
)

cc_library(
    name = "csr_processing_service",
    hdrs = ["csr_processing_client.hpp"],
    visibility = ["//visibility:public"],
    deps = [
        "//score/crypto/src/common:csr_wire",
        "//score/crypto/src/api/control_plane",
        "//score/crypto/src/api/data_plane:data_plane_client",
    ],
)

cc_library(
    name = "csr_processing_client",
    srcs = ["csr_processing_client.cpp"],
    visibility = ["//visibility:public"],
    deps = [
        ":csr_processing_service",
        "//score/crypto/src/daemon/mediator:mediator_operations",
    ],
)

cc_test(
    name = "csr_api_provider_test",
    srcs = ["csr_api_provider_test.cpp"],
    target_compatible_with = select({
        "//score/crypto/src/backend:openssl_backend_active": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    deps = [
        ":csr_template_library",
        "//score/crypto/src/daemon/provider/score_provider/openssl:csr_processing",
        "//score/crypto/src/api:crypto_stack",
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/key_management:key_management_headers",
        "//score/crypto/src/daemon/provider:provider_headers",
        "//score/crypto/src/daemon/provider/handler:crypto_handler_factory_headers",
        "//score/crypto/src/daemon/provider/handler:csr_handler_operations",
        "//score/crypto/src/daemon/provider/score_provider/openssl:provider_openssl_library",
        "//third_party/openssl:openssl_shared",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "csr_template_library",
    srcs = ["csr_template_client.cpp"],
    visibility = ["//visibility:public"],
    deps = [
        ":csr_request",
        ":csr_template_types",
        ":csr_processing_client",
        "//score/crypto/src/api:crypto_stack",
        "//score/crypto/src/api/config:context_configs",
        "//score/crypto/src/api/contexts:crypto_contexts",
    ],
)

cc_test(
    name = "csr_request_test",
    srcs = ["csr_request_test.cpp"],
    deps = [
        ":csr_request",
        "//score/crypto/src/daemon/provider/score_provider/openssl:csr_processing",
        "//score/crypto/src/common:csr_der",
        "//score/crypto/src/daemon/provider/handler:csr_handler_operations",
        "//third_party/openssl:openssl_shared",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "csr_template_test",
    srcs = ["csr_template_test.cpp"],
    deps = [
        ":csr_template_library",
        "//score/crypto/src/daemon/provider/score_provider/openssl:csr_processing",
        "//score/crypto/src/common:csr_der",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "csr_request",
    srcs = ["csr_request_client.cpp"],
    visibility = ["//visibility:public"],
    deps = [
        "//score/crypto/src/api/common:crypto_common",
        ":csr_request_types",
        ":csr_processing_service",
        "//score/crypto/src/daemon/provider/handler:csr_handler_operations",
        "@score_baselibs//score/language/futurecpp",
        "@score_baselibs//score/result",
    ],
)

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

load("@rules_cc//cc:cc_library.bzl", "cc_library")
load("@rules_cc//cc:cc_test.bzl", "cc_test")

cc_test(
    name = "cert_object_response_builder_test",
    srcs = ["query/cert_object_response_builder_test.cpp"],
    deps = [
        ":cert_management",
        ":cert_management_headers",
        ":cert_management_runtime_headers",
        ":cert_object_response_builder",
        "//score/crypto/src/daemon/common",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "cert_registry_test",
    srcs = ["core/cert_registry_test.cpp"],
    deps = [
        ":cert_management",
        ":cert_management_headers",
        ":cert_management_runtime_headers",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "access_policy_enforcer_test",
    srcs = ["policy/access_policy_enforcer_test.cpp"],
    deps = [
        ":cert_management",
        ":cert_management_headers",
        ":cert_management_runtime_headers",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "file_backed_slot_handler_test",
    srcs = ["slot/file_backed_slot_handler_test.cpp"],
    deps = [
        ":cert_management",
        ":cert_management_headers",
        ":cert_management_internal_headers",
        "//score/crypto/src/daemon/cert_management/tests:test_environment",
        "//score/crypto/src/daemon/common/storage:kv_deployment",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "slot_handler_factory_test",
    srcs = ["slot/slot_handler_factory_test.cpp"],
    deps = [
        ":cert_management",
        ":cert_management_headers",
        ":cert_management_internal_headers",
        "//score/crypto/src/daemon/provider:provider_headers",
        "//score/crypto/src/daemon/provider:provider_manager",
        "//score/crypto/src/daemon/provider/cert_management:cert_parser_headers",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "cert_object_response_builder",
    srcs = ["query/cert_object_response_builder.cpp"],
    hdrs = ["query/cert_object_response_builder.hpp"],
    visibility = [
        "//score/crypto/src/daemon:__pkg__",
        "//score/crypto/src/daemon:__subpackages__",
        "//tools/coverage:__pkg__",
    ],
    linkstatic = True,
    deps = [
        ":cert_management",
        ":cert_management_headers",
        ":cert_management_runtime_headers",
        ":cert_management_daemon_headers",
        "//score/crypto/src/api/types:certificate_types",
        "//score/crypto/src/daemon/common",
    ],
)

cc_library(
    name = "cert_management_headers",
    hdrs = [
        "interfaces/access_policy.hpp",
        "interfaces/cert_object.hpp",
        "interfaces/cert_slot_config.hpp",
        "interfaces/cert_types.hpp",
        "interfaces/i_cert_slot_handler.hpp",
        "interfaces/i_trust_store_handler.hpp",
    ],
    visibility = [
        "//score/crypto/src/daemon:__pkg__",
        "//score/crypto/src/daemon:__subpackages__",
    ],
    linkstatic = True,
    deps = [
        "//score/crypto/src/api/types:certificate_types",
        "//score/crypto/src/api/types:common_types",
        "//score/crypto/src/common:common_types",
        "//score/crypto/src/daemon/common",
    ],
)

cc_library(
    name = "cert_management_runtime_headers",
    hdrs = [
        "core/cert_entry.hpp",
        "core/cert_registry.hpp",
        "interfaces/trust_store_config.hpp",
        "nodes/cert_data_node.hpp",
        "nodes/cert_slot_data_node.hpp",
        "nodes/trust_store_data_node.hpp",
        "policy/access_policy_enforcer.hpp",
        "slot/cert_slot_manager.hpp",
        "slot/slot_registry.hpp",
        "truststore/trust_store_handler.hpp",
        "truststore/trust_store_manager.hpp",
    ],
    visibility = [
        "//score/crypto/src/daemon:__subpackages__",
        "//score/crypto/tests/cert_management:__pkg__",
    ],
    linkstatic = True,
    deps = [
        ":cert_management_headers",
        "//score/crypto/src/api/types:certificate_types",
        "//score/crypto/src/api/types:common_types",
        "//score/crypto/src/common:common_types",
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/data_manager",
    ],
)

cc_library(
    name = "cert_management_slot_backend_headers",
    hdrs = [
        "slot/crl_handler.hpp",
        "slot/deployment_loader.hpp",
        "slot/deployment_writer.hpp",
    ],
    visibility = [
        "//score/crypto/src/daemon/cert_management:__pkg__",
        "//score/crypto/src/daemon/cert_management:__subpackages__",
        "//score/crypto/src/daemon/provider:__subpackages__",
    ],
    linkstatic = True,
    deps = [
        ":cert_management_headers",
        "//score/crypto/src/api/types:certificate_types",
        "//score/crypto/src/api/types:common_types",
        "//score/crypto/src/common:common_types",
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/common/storage:deployment_iface",
    ],
)

cc_library(
    name = "cert_management_internal_headers",
    hdrs = [
        "interfaces/i_cert_slot_catalog.hpp",
        "slot/config_driven_slot_catalog.hpp",
        "slot/file_backed_slot_handler.hpp",
        "slot/slot_handler_factory.hpp",
        "truststore/config_driven_trust_store_catalog.hpp",
    ],
    visibility = [
        "//score/crypto/src/daemon/cert_management:__pkg__",
        "//score/crypto/src/daemon/cert_management:__subpackages__",
        "//score/crypto/tests/cert_management:__pkg__",
    ],
    linkstatic = True,
    deps = [
        ":cert_management_headers",
        ":cert_management_runtime_headers",
        ":cert_management_slot_backend_headers",
        "//score/crypto/src/common:common_types",
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/config:config_types",
        "//score/crypto/src/daemon/provider:provider_headers",
        "//score/crypto/src/daemon/provider/cert_management:cert_parser_headers",
    ],
)

cc_library(
    name = "cert_management_daemon_headers",
    hdrs = [
        "cert_management_module.hpp",
        "core/cert_management_service.hpp",
    ],
    visibility = [
        "//score/crypto/src/daemon:__pkg__",
        "//score/crypto/src/daemon:__subpackages__",
    ],
    linkstatic = True,
    deps = [
        ":cert_management_headers",
        ":cert_management_runtime_headers",
        "//score/crypto/src/api/types:certificate_types",
        "//score/crypto/src/api/types:common_types",
        "//score/crypto/src/common:common_types",
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/config:config_types",
        "//score/crypto/src/daemon/data_manager",
        "//score/crypto/src/daemon/provider:provider_headers",
    ],
)

cc_library(
    name = "cert_management",
    srcs = [
        "cert_management_module.cpp",
        "core/cert_management_service.cpp",
        "core/cert_registry.cpp",
        "interfaces/i_cert_slot_handler.cpp",
        "policy/access_policy_enforcer.cpp",
        "slot/config_driven_slot_catalog.cpp",
        "truststore/config_driven_trust_store_catalog.cpp",
        "slot/crl_handler.cpp",
        "slot/deployment_loader.cpp",
        "slot/deployment_writer.cpp",
        "slot/file_backed_slot_handler.cpp",
        "slot/cert_slot_manager.cpp",
        "slot/slot_handler_factory.cpp",
        "slot/slot_registry.cpp",
        "truststore/trust_store_handler.cpp",
        "truststore/trust_store_manager.cpp",
    ],
    linkstatic = True,
    visibility = [
        "//score/crypto/src/daemon:__pkg__",
        "//score/crypto/src/daemon:__subpackages__",
        "//score/crypto/tests/cert_management:__pkg__",
    ],
    deps = [
        ":cert_management_headers",
        ":cert_management_runtime_headers",
        ":cert_management_slot_backend_headers",
        ":cert_management_internal_headers",
        ":cert_management_daemon_headers",
        "//score/crypto/src/daemon/common/storage:file_io",
        "//score/crypto/src/daemon/common/storage:kv_deployment",
        "//score/crypto/src/daemon/config",
        "//score/crypto/src/daemon/provider:provider_manager",
        "//score/crypto/src/daemon/provider/cert_management:cert_management_provider_headers",
        "@score_baselibs//score/mw/log",
    ],
)

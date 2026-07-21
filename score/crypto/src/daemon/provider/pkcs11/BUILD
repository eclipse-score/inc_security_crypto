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

load("@rules_cc//cc:defs.bzl", "cc_library")

cc_library(
    name = "provider_pkcs11_headers",
    hdrs = [
        "detail/pkcs11_algorithm_info.hpp",
        "key_management/pkcs11_key_factory.hpp",
        "key_management/pkcs11_key_handler.hpp",
        "key_management/pkcs11_key_slot_handler.hpp",
        "key_management/pkcs11_key_store.hpp",
        "operations/factory/pkcs11_handler_factory.hpp",
        "operations/hash/pkcs11_hash_context.hpp",
        "operations/hash/pkcs11_hash_executor.hpp",
        "operations/hash/pkcs11_hash_handler.hpp",
        "operations/key_management/pkcs11_key_management_handler.hpp",
        "operations/mac/pkcs11_mac_context.hpp",
        "operations/mac/pkcs11_mac_executor.hpp",
        "operations/mac/pkcs11_mac_handler.hpp",
        "pkcs11_module.hpp",
        "pkcs11_provider.hpp",
        "pkcs11_provider_factory.hpp",
        "pkcs11_session_guard.hpp",
    ],
    includes = ["."],
    visibility = [
        "//:__subpackages__",
    ],
)

cc_library(
    name = "provider_pkcs11_library",
    srcs = [
        "key_management/pkcs11_key_factory.cpp",
        "key_management/pkcs11_key_handler.cpp",
        "key_management/pkcs11_key_slot_handler.cpp",
        "key_management/pkcs11_key_store.cpp",
        "operations/factory/pkcs11_handler_factory.cpp",
        "operations/hash/pkcs11_hash_executor.cpp",
        "operations/hash/pkcs11_hash_handler.cpp",
        "operations/key_management/pkcs11_key_management_handler.cpp",
        "operations/mac/pkcs11_mac_executor.cpp",
        "operations/mac/pkcs11_mac_handler.cpp",
        "pkcs11_module.cpp",
        "pkcs11_provider.cpp",
    ],
    includes = ["."],
    linkstatic = True,
    visibility = ["//:__subpackages__"],
    deps = [
        ":provider_pkcs11_headers",
        "//score/crypto/daemon/common",
        "//score/crypto/daemon/common:algorithm_info",
        "//score/crypto/daemon/key_management",
        "//score/crypto/daemon/provider:provider_headers",
        "//score/crypto/daemon/provider/executors:key_mgmt_executor",
        "//score/crypto/daemon/provider/handler:handler_utils_impl",
        "//score/crypto/daemon/provider/handler:hash_handler_operations",
        "//score/crypto/daemon/provider/handler:mac_handler_operations",
        "//third_party/soft_hsm:libsofthsm_shared",
        "@score_baselibs//score/result",
    ],
)

cc_library(
    name = "pkcs11_token_config",
    hdrs = ["pkcs11_token_config.hpp"],
    visibility = ["//:__subpackages__"],
)

cc_library(
    name = "provider_pkcs11_factory",
    srcs = [
        "pkcs11_provider_factory.cpp",
        "pkcs11_token_config.cpp",
    ],
    hdrs = ["pkcs11_provider_factory.hpp"],
    visibility = ["//:__subpackages__"],
    deps = [
        ":pkcs11_token_config",
        ":provider_pkcs11_library",
        "//score/crypto/daemon/provider:provider_headers",
    ],
)

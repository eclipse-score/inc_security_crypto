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
# *******************************************************************************
# Copyright (c) 2026 Contributors to the Eclipse Foundation
# SPDX-License-Identifier: Apache-2.0
# *******************************************************************************
load("@rules_cc//cc:cc_library.bzl", "cc_library")

cc_library(
    name = "cert_management_headers",
    hdrs = glob([
        "interfaces/*.hpp",
        "core/*.hpp",
        "nodes/*.hpp",
        "policy/*.hpp",
        "slot/*.hpp",
        "truststore/*.hpp",
        "detail/*.hpp",
        "cert_management_module.hpp",
    ]),
    includes = ["."],
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/src/api/common:crypto_common",
        "//score/crypto/src/api/config:context_configs",
        "//score/crypto/src/common:common_types",
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/common/storage:deployment_iface",
        "//score/crypto/src/daemon/data_manager",
        "//score/crypto/src/daemon/key_management:key_handler_iface",
        "//score/crypto/src/daemon/provider:provider_headers",
        "//score/crypto/src/daemon/provider/cert_management:cert_parser_headers",
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
        "slot/slot_registry.cpp",
        "truststore/trust_store_handler.cpp",
        "truststore/trust_store_manager.cpp",
    ],
    includes = ["."],
    linkstatic = True,
    visibility = ["//:__subpackages__"],
    deps = [
        ":cert_management_headers",
        "//score/crypto/src/daemon/common/storage:file_io",
        "//score/crypto/src/daemon/common/storage:kv_deployment",
        "//score/crypto/src/daemon/config",
        "//score/crypto/src/daemon/provider:provider_manager",
        "//score/crypto/src/daemon/provider/cert_management:cert_management_provider_headers",
        "@score_baselibs//score/mw/log",
    ],
)

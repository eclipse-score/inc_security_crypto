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

# Header-only library: operation constants only (no key management infra deps)
cc_library(
    name = "key_management_operations",
    hdrs = ["interfaces/key_management_operations.hpp"],
    visibility = ["//:__subpackages__"],
    deps = ["//score/crypto/daemon/common"],
)

# Minimal leaf target: IKeyHandler + key_types only.
# No dep on handler_headers — breaks the handler_headers <-> key_management_headers cycle.
# Both handler_headers and key_management_headers depend on this target.
cc_library(
    name = "key_handler_iface",
    hdrs = [
        "interfaces/i_key_handler.hpp",
        "interfaces/key_types.hpp",
    ],
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/common:common_types",
        "//score/crypto/daemon/common",
        "//score/mw/crypto/api/common:crypto_common",
        "//score/mw/crypto/api/config:context_configs",
    ],
)

# Header-only library: interfaces, config types, operations, guards, data nodes
cc_library(
    name = "key_management_headers",
    hdrs = [
        # interfaces/
        "interfaces/i_key_factory.hpp",
        "interfaces/i_key_slot_catalog.hpp",
        "interfaces/i_key_slot_handler.hpp",
        "interfaces/key_management_operations.hpp",
        "interfaces/key_slot_config.hpp",
        # slot/
        "slot/access_policy_enforcer.hpp",
        "slot/config_driven_slot_catalog.hpp",
        "slot/deployment_loader.hpp",
        "slot/deployment_writer.hpp",
        "slot/file_backed_slot_handler.hpp",
        "slot/slot_registry.hpp",
        # nodes/
        "nodes/key_data_node.hpp",
        "nodes/key_slot_data_node.hpp",
        # core/
        "core/key_entry.hpp",
        "core/key_management_service.hpp",
        "core/key_registry.hpp",
        # detail/
        "detail/slot_info_builder.hpp",
        # root/
        "key_management_module.hpp",
    ],
    includes = ["."],
    visibility = [
        "//:__subpackages__",
    ],
    deps = [
        ":key_handler_iface",
        "//score/crypto/daemon/common",
        "//score/crypto/daemon/control_plane:request_handler_hdr",
        "//score/crypto/daemon/data_manager",
        "//score/crypto/daemon/provider/handler:handler_headers",
        "//score/mw/crypto/api/common:crypto_common",
        "//score/mw/crypto/api/config:context_configs",
    ],
)

# Implementation library: compiled sources
cc_library(
    name = "key_management",
    srcs = [
        # interfaces/ (default implementations for virtual methods)
        "interfaces/i_key_factory.cpp",
        "interfaces/i_key_slot_handler.cpp",
        # slot/
        "slot/access_policy_enforcer.cpp",
        "slot/config_driven_slot_catalog.cpp",
        "slot/deployment_loader.cpp",
        "slot/deployment_writer.cpp",
        "slot/file_backed_slot_handler.cpp",
        "slot/slot_registry.cpp",
        # core/
        "core/key_management_service.cpp",
        "core/key_registry.cpp",
        # root/
        "key_management_module.cpp",
    ],
    includes = ["."],
    linkstatic = True,
    visibility = ["//:__subpackages__"],
    deps = [
        ":key_management_headers",
        "//score/crypto/daemon/common",
        "//score/crypto/daemon/data_manager",
        "//score/crypto/daemon/key_management/slot/deployment:kv_deployment",
        "//score/crypto/daemon/provider:provider_headers",
        "//score/crypto/daemon/provider:provider_manager",
        "//score/mw/crypto/api/common:crypto_common",
    ],
)

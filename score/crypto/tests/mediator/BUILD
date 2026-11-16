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

# Minimal mediator component test. The real certificate management module is registered through the
# MediatorFactory path the daemon uses, and certificate contexts are created through processRequest.
cc_test(
    name = "test_mediator_cert_contexts",
    srcs = ["test_mediator_cert_contexts.cpp"],
    target_compatible_with = select({
        "//score/crypto/src/backend:openssl_backend_active": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    deps = [
        "//score/crypto/src/daemon/cert_management:cert_management",
        "//score/crypto/src/daemon/cert_management:cert_management_daemon_headers",
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/common/context:context_registration",
        "//score/crypto/src/daemon/common/context:context_types",
        "//score/crypto/src/daemon/config:config_types",
        "//score/crypto/src/daemon/control_plane:control_plane",
        "//score/crypto/src/daemon/data_manager:data_manager",
        "//score/crypto/src/daemon/key_management:key_management",
        "//score/crypto/src/daemon/key_management:key_management_headers",
        "//score/crypto/src/daemon/mediator:mediator",
        "//score/crypto/src/daemon/mediator:mediator_operations",
        "//score/crypto/src/daemon/provider:provider_manager",
        "//score/crypto/src/daemon/provider/score_provider/openssl:provider_openssl_headers",
        "//score/crypto/src/daemon/provider/score_provider/openssl:provider_openssl_library",
        "@googletest//:gtest_main",
    ],
)

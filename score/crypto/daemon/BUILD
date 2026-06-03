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

load("@rules_cc//cc:defs.bzl", "cc_binary")

cc_binary(
    name = "crypto_daemon",
    srcs = ["src/daemon.cpp"],
    copts = select({
        "//conditions:default": [],
        ":tsan_enabled": [
            "-fsanitize=thread",
            "-g",
            "-O1",
        ],
    }),
    dynamic_deps = [
        "//third_party/openssl:openssl_shared",
        "//third_party/grpc:libgrpc_shared",
    ],
    includes = ["IPC"],
    linkopts = select({
        "//conditions:default": [],
        ":tsan_enabled": [
            "-fsanitize=thread",
        ],
    }),
    linkstatic = True,
    visibility = ["//tests:__subpackages__"],
    deps = [
        "//score/crypto/daemon/config",
        "//score/crypto/daemon/control_plane",
        "//score/crypto/daemon/data_manager",
        "//score/crypto/daemon/mediator",
        "//score/crypto/daemon/provider:provider_manager",
        "//score/crypto/daemon/provider/pkcs11:provider_pkcs11_factory",
        "//score/crypto/daemon/provider/score_provider:score_provider_factory",
        "//score/crypto/ipc:ipc_config",
        "//score/crypto/ipc/grpc_adapter:grpc_control_server",
    ],
)

# Configuration for enabling ThreadSanitizer
config_setting(
    name = "tsan_enabled",
    values = {
        "define": "tsan=1",
    },
)

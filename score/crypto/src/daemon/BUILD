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
    visibility = ["//visibility:public"],
    deps = [
        "//score/crypto/src/daemon/config",
        "//score/crypto/src/daemon/control_plane",
        "//score/crypto/src/daemon/data_manager",
        "//score/crypto/src/daemon/mediator",
        "//score/crypto/src/daemon/provider:provider_manager_factory",
        "//score/crypto/src/ipc:ipc_config",
        "//score/crypto/src/ipc/grpc_adapter:grpc_control_server",
    ],
)

# Configuration for enabling ThreadSanitizer
config_setting(
    name = "tsan_enabled",
    values = {
        "define": "tsan=1",
    },
)

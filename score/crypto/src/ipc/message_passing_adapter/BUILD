# *******************************************************************************
# Copyright (c) 2026 Contributors to the Eclipse Foundation
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
# *******************************************************************************

load("@rules_cc//cc:defs.bzl", "cc_library")

cc_library(
    name = "ipc_config",
    hdrs = ["ipc_config.h"],
    linkstatic = True,
    visibility = ["//:__subpackages__"],
    deps = ["//score/crypto/src/ipc/protocol:protocol_config"],
)

cc_library(
    name = "message_passing_client",
    hdrs = [
        "client/client_session/client_session.h",
        "client/message_passing_control_client.h",
        "client/client_session/pending_call.h",
        "client/client_session/pending_call_registry.h",
    ],
    srcs = [
        "client/client_session/client_session.cpp",
        "client/message_passing_control_client.cpp",
        "client/client_session/pending_call.cpp",
        "client/client_session/pending_call_registry.cpp",
    ],
    linkstatic = True,
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/src/ipc/protocol:protocol",
        "//score/crypto/src/api/common:crypto_common",
        "//score/crypto/src/api/control_plane:control_plane_hdr",
        "//score/crypto/src/common:common_types",
        "//score/crypto/src/daemon/control_plane",
        ":ipc_config",
        "@score_baselibs//score/language/futurecpp",
        "@score_baselibs//score/mw/log",
        "@score_communication//score/message_passing:message_passing",
    ],
)

cc_library(
    name = "message_passing_server",
    srcs = [
        "server/message_passing_control_server.cpp",
        "server/server_state_machine.cpp",
        "server/work_item_execution/fixed_worker_work_item_executor.cpp",
        "server/session/session.cpp",
        "server/session/work_item.cpp",
        "server/session/session_manager.cpp",
        "server/session/session_registry.cpp",
        "server/session/work_item_dispatcher.cpp",
    ],
    hdrs = [
        "server/message_passing_control_server.h",
        "server/server_callbacks.hpp",
        "server/server_state_machine.h",
        "server/work_item_execution/i_work_item_submitter.h",
        "server/work_item_execution/fixed_worker_work_item_executor.h",
        "server/session/session.h",
        "server/session/work_item.h",
        "server/session/session_manager.h",
        "server/session/session_registry.h",
        "server/session/work_item_dispatcher.h",
    ],
    linkstatic = True,
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/src/ipc/protocol:protocol",
        "//score/crypto/src/daemon/control_plane",
        ":ipc_config",
        "@score_baselibs//score/language/futurecpp",
        "@score_baselibs//score/mw/log",
        "@score_communication//score/message_passing:message_passing",
    ],
)

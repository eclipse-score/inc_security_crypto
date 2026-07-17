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
load("//score/crypto/src/backend:backend_exports.bzl", "BACKEND_DEFINES")

# Score provider backend - provides ScoreProviderConfig::ParseConfig() with
# default behaviour: discover all active backends via GetActiveBackends().
#
# active_score_backends is in deps (not implementation_deps) so that
# score_provider_factory can still call GetActiveBackends() transitively
# via this target without needing a direct dep on active_score_backends.
cc_library(
    name = "backend",
    srcs = ["score_provider_config_parser.cpp"],
    visibility = ["//visibility:public"],
    deps = [
        "//score/crypto/src/backend:active_score_backends",
        "//score/crypto/src/daemon/provider/score_provider:score_provider_config",
    ],
)

# Lightweight: preprocessor defines + discovery header only.
# Consumed by any target that needs to know which score provider backends are enabled
# (e.g. provider_manager_factory) without pulling in adapter implementations.
cc_library(
    name = "score_backend_defines",
    hdrs = ["active_backends_list.hpp"],
    defines = BACKEND_DEFINES,
    visibility = ["//visibility:public"],
    deps = [
        "//score/crypto/src/daemon/provider/score_provider:score_backend_adapter",
    ],
)

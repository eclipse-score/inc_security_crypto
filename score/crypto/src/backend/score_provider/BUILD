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

# Score provider backend - provides ScoreProviderConfig::ParseConfig(config) with
# default behaviour: discover all active backends via GetActiveBackends().
#
# active_score_backends is in deps (not implementation_deps) so that
# score_provider_factory can still call GetActiveBackends() transitively
# via this target without needing a direct dep on active_score_backends.
cc_library(
    name = "backend",
    srcs = ["score_provider_config_parser.cpp"],
    target_compatible_with = select({
        "//score/crypto/src/backend:score_backend_enabled": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    visibility = ["//visibility:public"],
    deps = [
        "//score/crypto/src/backend:active_score_backends",
        "//score/crypto/src/daemon/provider/score_provider:score_provider_config",
    ],
)

# Lightweight: discovery header, preprocessor defines, and adapter interface.
# Consumed by active_score_backends to expose the active backend list without
# pulling in adapter implementations.
#
# Individual sub-backend defines (SCORE_BACKEND_OPENSSL_ENABLED, etc.) propagate
# from each sub-backend's *_backend_define target listed in deps.
# To add a new score backend:
#   1. Create score_provider/<backend>/BUILD with the three-target pattern.
#   2. Add a bool_flag + config_setting in //score/crypto/src/backend:BUILD.
#   3. Add its *_backend_define to deps here.
#   4. Add its *_backend    to all_score_backends.deps below.
cc_library(
    name = "score_backend_headers",
    hdrs = ["active_backends_list.hpp"],
    target_compatible_with = select({
        "//score/crypto/src/backend:score_backend_enabled": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    visibility = ["//visibility:public"],
    deps = [
        "//score/crypto/src/daemon/provider/score_provider:score_backend_adapter",
        "//score/crypto/src/backend/score_provider/openssl:openssl_backend_define",
        # To add a new score backend: add its *_backend_define dep here (step 3).
    ],
)

# Heavy: aggregates all active sub-backend adapter targets.
# Only active_score_backends (//score/crypto/src/backend:BUILD) should consume this.
# The master enable/disable gate lives there; this target is unconditionally listed.
cc_library(
    name = "all_score_backends",
    target_compatible_with = select({
        "//score/crypto/src/backend:score_backend_enabled": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    visibility = ["//score/crypto/src/backend:__pkg__"],
    deps = [
        "//score/crypto/src/backend/score_provider/openssl:openssl_backend",
        # To add a new score backend: add its *_backend dep here (step 4).
    ],
)

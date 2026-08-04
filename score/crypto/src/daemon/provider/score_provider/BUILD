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

# Abstract base provider for the score interface family.
cc_library(
    name = "score_provider",
    srcs = ["src/score_provider.cpp"],
    hdrs = ["score_provider.hpp"],
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/src/daemon/provider:provider_headers",
        "//score/crypto/src/daemon/provider/handler:crypto_handler_factory_headers",
    ],
)

cc_library(
    name = "score_provider_config",
    srcs = ["src/score_provider_config.cpp"],
    hdrs = ["score_provider_config.hpp"],
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/src/common:common_types",
        "//score/crypto/src/daemon/common",
    ],
)

# Backend adapter interface (used by backend adapters to register with score provider).
cc_library(
    name = "score_backend_adapter",
    hdrs = ["score_backend_adapter.hpp"],
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/src/daemon/provider:provider_headers",
    ],
)

# Top-level factory for the score interface family.
cc_library(
    name = "score_provider_factory",
    srcs = [
        "src/score_provider_factory.cpp",
    ],
    hdrs = ["score_provider_factory.hpp"],
    implementation_deps = [
        "//score/crypto/src/backend/score_provider:backend",  # Selected Score backends
    ],
    visibility = ["//:__subpackages__"],
    deps = [
        ":score_provider",
        ":score_provider_config",
        "//score/crypto/src/daemon/provider:provider_headers",
    ],
)

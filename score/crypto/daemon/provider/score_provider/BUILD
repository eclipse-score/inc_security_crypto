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
        "//score/crypto/daemon/provider:provider_headers",
        "//score/crypto/daemon/provider/handler:crypto_handler_factory_headers",
    ],
)

# Score provider configuration (header-only entry struct + config class).
cc_library(
    name = "score_provider_config",
    hdrs = ["score_provider_config.hpp"],
    visibility = ["//:__subpackages__"],
)

# Top-level factory for the score interface family.
cc_library(
    name = "score_provider_factory",
    srcs = [
        "src/score_provider_config.cpp",
        "src/score_provider_factory.cpp",
    ],
    hdrs = ["score_provider_factory.hpp"],
    visibility = ["//:__subpackages__"],
    deps = [
        ":score_provider",
        ":score_provider_config",
        "//score/crypto/daemon/provider:provider_headers",
        "//score/crypto/daemon/provider/score_provider/openssl:provider_openssl_factory",
    ],
)

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

cc_library(
    name = "provider_headers",
    hdrs = [
        "i_provider.hpp",
        "i_provider_factory.hpp",
        "provider_manager.hpp",
    ],
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/daemon/common",
        "//score/crypto/daemon/config",
        "//score/crypto/daemon/provider/handler:context_node",
        "//score/crypto/daemon/provider/handler:crypto_handler_factory_headers",
    ],
)

cc_library(
    name = "provider_manager",
    srcs = ["src/provider_manager.cpp"],
    visibility = ["//:__subpackages__"],
    deps = [
        ":provider_headers",
    ],
)

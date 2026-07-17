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

# ============================================================================
# OpenSSL Backend Adapter
#
# Provides registration/enablement layer for OpenSSL score provider backend.
# The actual OpenSSL provider implementation lives in
# daemon/provider/score_provider/openssl/.
# ============================================================================

cc_library(
    name = "openssl_backend_adapter",
    srcs = ["openssl_backend_adapter.cpp"],
    hdrs = ["openssl_backend_adapter.hpp"],
    visibility = [
        "//score/crypto/src/backend:__pkg__",  # For active_backends_list.hpp
    ],
    deps = [
        "//score/crypto/src/daemon/provider/score_provider:score_backend_adapter",
        "//score/crypto/src/daemon/provider/score_provider/openssl:provider_openssl_library",
    ],
)

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

cc_library(
    name = "context_configs",
    hdrs = [
        "base_context_config.hpp",
        "hash_context_config.hpp",
        "key_management_context_config.hpp",
        "key_operation_params.hpp",
        "mac_context_config.hpp",
        "permission_builder.hpp",
    ],
    includes = ["."],
    visibility = ["//visibility:public"],
    deps = [
        "//score/mw/crypto/api/common:crypto_common",
    ],
)

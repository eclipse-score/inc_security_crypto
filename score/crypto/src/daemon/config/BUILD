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

# Export FlatBuffers schema for use by tests
filegroup(
    name = "crypto_config_fbs_schema",
    srcs = ["crypto_config.fbs"],
    visibility = ["//:__subpackages__"],
)

genrule(
    name = "generated_crypto_config",
    srcs = ["crypto_config_fbs_schema"],
    outs = [
        "crypto_config_generated.h",
    ],
    cmd = "$(location @flatbuffers//:flatc) --cpp -o $(@D) $(SRCS)",
    tools = ["@flatbuffers//:flatc"],
)

# Configuration types and structures (headers only)
cc_library(
    name = "config_types",
    hdrs = ["inc/config.hpp"],
    includes = ["inc"],
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/daemon/common",
        "//score/crypto/daemon/provider/pkcs11:pkcs11_token_config",
        "//score/crypto/daemon/provider/score_provider:score_provider_config",
    ],
)

# FlatBuffers configuration parser
cc_library(
    name = "flatbuffer_config_parser",
    srcs = [
        "src/flatbuffer_config_parser.cpp",
        ":generated_crypto_config",
    ],
    hdrs = [
        "src/flatbuffer_config_parser.hpp",
        ":generated_crypto_config",
    ],
    includes = ["inc"],
    visibility = ["//:__subpackages__"],
    deps = [
        ":config_types",
        "//score/crypto/common:common_types",
        "//score/crypto/daemon/common",
        "@flatbuffers",
        "@score_baselibs//score/mw/log",
    ],
)

cc_library(
    name = "config",
    srcs = ["src/config.cpp"],
    includes = ["inc"],
    visibility = ["//:__subpackages__"],
    deps = [
        ":config_types",
        ":flatbuffer_config_parser",
        "//score/crypto/daemon/common",
    ],
)

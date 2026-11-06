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

load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
load("@score_baselibs//score/flatbuffers/bazel:codegen.bzl", "generate_cpp")
load("@score_baselibs//score/flatbuffers/bazel:tools.bzl", "generate_json_schema")

filegroup(
    name = "pkcs11_config_fbs_schema",
    srcs = ["pkcs11_config.fbs"],
    visibility = ["//visibility:public"],
)

generate_cpp(
    name = "generated_pkcs11_config",
    output = "pkcs11_config_generated.h",
    schema = "pkcs11_config.fbs",
)

generate_json_schema(
    name = "pkcs11_config_json_schema",
    output = "pkcs11_config.schema.json",
    schema = "pkcs11_config.fbs",
    visibility = ["//visibility:public"],
)

cc_library(
    name = "pkcs11_config_schema",
    hdrs = [":generated_pkcs11_config"],
    deps = [
        "@score_baselibs//score/flatbuffers:flatbufferscpp",
        "@score_baselibs//score/flatbuffers/common:buffer_version_generated_bare",
    ],
)

# Pkcs11Config::ParseConfig(config_path) implementation.
#
# This is a fixed dependency of active_pkcs11_backend and is always present
# when PKCS#11 is enabled, regardless of which backend library is selected via
# the pkcs11_backend label_flag.
#
# Parses the optional backend-owned FlatBuffer configuration. When no runtime
# configuration reference is supplied, the existing build-selected test
# defaults remain available for backward compatibility.
#
# Backend subdirectories (softhsm/, vendor_hsm/, etc.) provide only the
# PKCS#11 library and headers — they do NOT own config parsing.
#
# To use a different PKCS#11 library, override the label_flag at build time:
#   --//score/crypto/src/backend:pkcs11_backend=//third_party/your_hsm:your_hsm
# Or change the build_setting_default in backend/BUILD.
cc_library(
    name = "pkcs11_config_parser",
    srcs = ["pkcs11_token_config_parser.cpp"],
    defines = select({
        "//score/crypto/src/backend:rust_cryptoki_selected": ["USE_RUST_PKCS11=1"],
        "//conditions:default": [],
    }),
    target_compatible_with = select({
        "//score/crypto/src/backend:pkcs11_backend_enabled": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    visibility = ["//score/crypto/src/backend:__pkg__"],
    deps = [
        ":pkcs11_config_schema",
        "//score/crypto/src/daemon/common/storage:file_io",
        "//score/crypto/src/daemon/provider/pkcs11:pkcs11_token_config",
        "@score_baselibs//score/flatbuffers:flatbufferutils",
        "@score_baselibs//score/mw/log",
    ],
)

cc_test(
    name = "pkcs11_config_parser_unit_test",
    srcs = ["pkcs11_token_config_parser_test.cpp"],
    target_compatible_with = select({
        "//score/crypto/src/backend:pkcs11_backend_enabled": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    deps = [
        ":pkcs11_config_parser",
        ":pkcs11_config_schema",
        "//score/crypto/src/daemon/provider/pkcs11:pkcs11_token_config",
        "@googletest//:gtest_main",
    ],
)

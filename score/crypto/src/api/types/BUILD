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
    name = "common_types",
    hdrs = ["common.hpp"],
    includes = ["."],
    visibility = ["//visibility:public"],
    deps = ["//score/crypto/src/api/common:crypto_common_base"],
)

cc_library(
    name = "certificate_types",
    hdrs = ["certificate.hpp"],
    includes = ["."],
    visibility = ["//visibility:public"],
    deps = [
        ":common_types",
        "//score/crypto/src/api/common:crypto_common",
        "@score_baselibs//score/result",
    ],
)

cc_library(
    name = "key_types",
    hdrs = ["key.hpp"],
    includes = ["."],
    visibility = ["//visibility:public"],
    deps = [":common_types"],
)

cc_library(
    name = "types",
    hdrs = ["common.hpp", "certificate.hpp", "key.hpp"],
    includes = ["."],
    visibility = ["//visibility:public"],
    deps = [":certificate_types", ":key_types"],
)

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
    name = "deployment_iface",
    srcs = [
        "deployment_descriptor.cpp",
    ],
    hdrs = [
        "deployment_descriptor.hpp",
        "deployment_path_utils.hpp",
        "i_deployment_loader.hpp",
        "i_deployment_writer.hpp",
    ],
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/src/common:common_types",
        "//score/crypto/src/daemon/common",
    ],
)

cc_library(
    name = "file_io",
    srcs = ["file_io.cpp"],
    hdrs = ["file_io.hpp"],
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/src/common:common_types",
        "//score/crypto/src/daemon/common",
    ],
)

cc_library(
    name = "kv_deployment",
    srcs = [
        "kv/kv_deployment_loader.cpp",
        "kv/kv_deployment_writer.cpp",
    ],
    hdrs = [
        "kv/kv_deployment_loader.hpp",
        "kv/kv_deployment_writer.hpp",
    ],
    visibility = ["//:__subpackages__"],
    deps = [
        ":deployment_iface",
        ":file_io",
        "@score_baselibs//score/mw/log",
    ],
)

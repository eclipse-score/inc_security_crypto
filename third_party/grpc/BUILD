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

# Helper library to work around grpc not having proper symbol visibility for shared libraries.
#
# Bazel's cc_shared_library documentation states: "The rule implementation does not take
# care of informing the linker about which symbols should be exported. The user should
# take care of this via linker scripts or visibility declarations in the source code."
#
# Since grpc from Bazel Central Registry doesn't have visibility attributes (it's designed
# for static linking), we need this helper to ensure commonly-used APIs are included in
# the shared library by creating references to them.
cc_library(
    name = "grpc_symbol_reference",
    srcs = ["grpc_symbol_reference.cpp"],
    visibility = ["//visibility:private"],
    deps = ["@grpc//:grpc++_unsecure"],
    alwayslink = True,
)

cc_shared_library(
    name = "libgrpc_shared",
    shared_lib_name = "libgrpc++.so.1",
    visibility = ["//visibility:public"],
    deps = [
        ":grpc_symbol_reference",  # Forces inclusion of commonly-used grpc symbols
        "@grpc//:grpc++_unsecure",
    ],
)

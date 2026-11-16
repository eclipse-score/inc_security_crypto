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

genrule(
    name = "generated_csr_wire",
    srcs = ["csr_wire.fbs"],
    outs = ["csr_wire_generated.h"],
    cmd = "$(location @flatbuffers//:flatc) --cpp --scoped-enums --gen-object-api -o $(@D) $(SRCS)",
    tools = ["@flatbuffers//:flatc"],
)

cc_library(
    name = "csr_wire",
    srcs = ["csr_wire.cpp"],
    hdrs = ["csr_wire.hpp", ":generated_csr_wire"],
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/src/api/csr:csr_template_types",
        "@flatbuffers",
    ],
)

cc_library(
    name = "csr_der",
    srcs = ["csr_der.cpp"],
    hdrs = ["csr_der.hpp"],
    visibility = [
        "//score/crypto/src/common:__pkg__",
        "//score/crypto/src/daemon:__subpackages__",
        "//score/crypto/src/api/csr:__pkg__",  # Backend source and regression tests only.
        "//score/crypto/src/api/contexts:__pkg__",  # Regression test only.
    ],
    deps = [
        "//score/crypto/src/api/common:crypto_common",
        "//score/crypto/src/daemon/provider/handler:csr_handler_operations",
        "//third_party/openssl:openssl_shared",
        "@score_baselibs//score/language/futurecpp",
        "@score_baselibs//score/result",
    ],
)

cc_test(
    name = "csr_wire_test",
    srcs = ["csr_wire_test.cpp"],
    deps = [":csr_wire", "@googletest//:gtest_main"],
)

cc_test(
    name = "csr_der_test",
    srcs = ["csr_der_test.cpp"],
    deps = [
        ":csr_der",
        "//score/crypto/src/daemon/provider/handler:csr_handler_operations",
        "//third_party/openssl:openssl_shared",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "common_types",
    srcs = [
        "types.hpp",
    ],
    copts = [
        # Use baselibs expected implementation by default
        "-DSTD_LIB_CPP17=0",
    ],
    visibility = ["//:__subpackages__"],
    # Default: use baselibs/futurecpp expected
    # To switch to C++17 std lib: remove the deps below and set -DSTD_LIB_CPP17=1
    deps = [
        # Use results for deatils/expected, as it is not directly visible
        "@score_baselibs//score/result",
    ],
)

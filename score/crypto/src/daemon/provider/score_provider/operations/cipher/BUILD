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

# Cipher executor + abstract base cipher handler for the score interface family.
cc_library(
    name = "score_cipher_handler",
    srcs = [
        "src/cipher_executor.cpp",
        "src/score_cipher_handler.cpp",
    ],
    hdrs = [
        "cipher_executor.hpp",
        "score_cipher_handler.hpp",
    ],
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/common:algorithm_info",
        "//score/crypto/src/daemon/provider/handler:cipher_handler_operations",
        "//score/crypto/src/daemon/provider/handler:handler_headers",
        "//score/crypto/src/daemon/provider/handler:handler_utils_impl",
        "//score/crypto/src/api/common:crypto_common",
    ],
)

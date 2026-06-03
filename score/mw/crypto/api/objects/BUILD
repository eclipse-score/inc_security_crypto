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
    name = "crypto_objects",
    hdrs = [
        "i_crypto_object.hpp",
        "i_key_object.hpp",
        "i_key_slot_object.hpp",
        "i_private_key_object.hpp",
        "i_public_key_object.hpp",
        "i_symmetric_key_object.hpp",
    ],
    includes = ["."],
    visibility = ["//visibility:public"],
    deps = [
        "//score/mw/crypto/api/common:crypto_common",
        "@score_baselibs//score/language/futurecpp",
        "@score_baselibs//score/result",
    ],
)

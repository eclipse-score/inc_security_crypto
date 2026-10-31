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

load("@score_baselibs//score/flatbuffers/bazel:tools.bzl", "serialize_versioned_buffer")

genrule(
    name = "generate_integration_test_config",
    srcs = [
        "//score/crypto/src/daemon/config:crypto_config_fbs_schema",
        "integration_test_config.json",
    ],
    outs = ["integration_test_config.bin"],
    cmd = "$(location @flatbuffers//:flatc) -b -o $(@D) $(SRCS)",
    tools = ["@flatbuffers//:flatc"],
    visibility = ["//:__subpackages__"],
)

serialize_versioned_buffer(
    name = "generate_integration_pkcs11_config",
    buffer_major_version = 0,
    buffer_minor_version = 1,
    data = "integration_pkcs11_config.json",
    output = "integration_pkcs11_config.bin",
    schema = "//score/crypto/src/backend/pkcs11:pkcs11_config_fbs_schema",
    visibility = ["//:__subpackages__"],
)

filegroup(
    name = "integration_test_config",
    srcs = glob(["*.kv"]) + [
        ":generate_integration_pkcs11_config",
        ":generate_integration_test_config",
    ],
    visibility = ["//:__subpackages__"],
)

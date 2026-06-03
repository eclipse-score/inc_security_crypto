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

genrule(
    name = "generate_key_management_test_config",
    srcs = [
        "//score/crypto/daemon/config:crypto_config_fbs_schema",
        "key_management_test_config.json",
    ],
    outs = ["key_management_test_config.bin"],
    cmd = "$(location @flatbuffers//:flatc) -b -o $(@D) $(SRCS)",
    tools = ["@flatbuffers//:flatc"],
    visibility = ["//:__subpackages__"],
)

filegroup(
    name = "key_management_test_config",
    srcs = [":generate_key_management_test_config"],
    visibility = ["//:__subpackages__"],
)

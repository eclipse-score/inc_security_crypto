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
    name = "generate_provider_resource_test_configs",
    srcs = [
        "//score/crypto/src/daemon/config:crypto_config_fbs_schema",
        "provider_resource_empty_name_config.json",
        "provider_resource_test_config.json",
    ],
    outs = [
        "provider_resource_empty_name_config.bin",
        "provider_resource_test_config.bin",
    ],
    cmd = "$(location @flatbuffers//:flatc) -b -o $(@D) $(SRCS)",
    tools = ["@flatbuffers//:flatc"],
)

filegroup(
    name = "provider_resource_test_configs",
    srcs = [":generate_provider_resource_test_configs"],
    visibility = ["//:__subpackages__"],
)

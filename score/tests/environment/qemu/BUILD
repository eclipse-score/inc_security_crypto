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

load("@score_rules_imagefs//rules/qnx:ifs.bzl", "qnx_ifs")

exports_files(["qemu_config.json"])

qnx_ifs(
    name = "qnx_x86_64_ifs",
    srcs = [],
    build_file = "x86_64/init.build",
    extra_build_files = ["x86_64/tools.build"],
    tags = ["manual"],
    target_compatible_with = ["@platforms//os:qnx"],
    visibility = ["//visibility:public"],
)

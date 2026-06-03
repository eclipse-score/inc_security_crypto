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
# Custom platform definitions for QNX builds
# This wraps the score_bazel_platforms platform and adds the standard @platforms//os:qnx
# constraint so that select() statements in external dependencies (grpc, abseil) can match it.

platform(
    name = "x86_64-qnx-extended",
    constraint_values = [
        "@platforms//os:qnx",  # Add standard QNX OS constraint for select() matching
    ],
    parents = ["@score_bazel_platforms//:x86_64-qnx-sdp_8.0.0-posix"],
    visibility = ["//visibility:public"],
)

platform(
    name = "aarch64-qnx-extended",
    constraint_values = [
        "@platforms//os:qnx",  # Add standard QNX OS constraint for select() matching
    ],
    parents = ["@score_bazel_platforms//:aarch64-qnx-sdp_8.0.0-posix"],
    visibility = ["//visibility:public"],
)

# Config settings for selecting on OS + CPU combinations
config_setting(
    name = "is_qnx_aarch64",
    constraint_values = [
        "@platforms//os:qnx",
        "@platforms//cpu:aarch64",
    ],
    visibility = ["//visibility:public"],
)

config_setting(
    name = "is_qnx_x86_64",
    constraint_values = [
        "@platforms//os:qnx",
        "@platforms//cpu:x86_64",
    ],
    visibility = ["//visibility:public"],
)

config_setting(
    name = "is_linux_aarch64",
    constraint_values = [
        "@platforms//os:linux",
        "@platforms//cpu:aarch64",
    ],
    visibility = ["//visibility:public"],
)

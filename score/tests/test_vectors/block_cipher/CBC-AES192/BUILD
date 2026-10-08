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

load("@rules_pkg//pkg:mappings.bzl", "pkg_files", "strip_prefix")

filegroup(
    name = "block_cipher_test_vectors",
    srcs = glob(["*.bin"]),
    visibility = ["//visibility:public"],
)

pkg_files(
    name = "block_cipher_test_vectors_pkg",
    srcs = glob(["*.bin"]),
    # preserve test_vectors/block_cipher/CBC-AES192/ folders
    strip_prefix = strip_prefix.from_root("score/tests"),
    visibility = ["//visibility:public"],
)

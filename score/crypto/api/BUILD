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
    name = "operations",
    visibility = [
        "//:__subpackages__",
    ],
    deps = [
        "//score/crypto/daemon/control_plane:control_operations",
        "//score/crypto/daemon/key_management:key_management_operations",
        "//score/crypto/daemon/mediator:mediator_operations",
        "//score/crypto/daemon/provider/handler:hash_handler_operations",
        "//score/crypto/daemon/provider/handler:mac_handler_operations",
    ],
)

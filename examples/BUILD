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

load("@rules_cc//cc:defs.bzl", "cc_binary")

cc_binary(
    name = "hashing_example",
    srcs = ["hashing_example.cpp"],
    deps = [
        "//score/mw/crypto/api:crypto_stack",
        "//score/mw/crypto/api/config:context_configs",
        "//score/mw/crypto/api/contexts:crypto_contexts",
    ],
)

cc_binary(
    name = "memory_allocator_example",
    srcs = ["memory_allocator_example.cpp"],
    deps = [
        "//score/mw/crypto/api:crypto_stack",
        "//score/mw/crypto/api/common:crypto_common",
        "//score/mw/crypto/api/config:context_configs",
        "//score/mw/crypto/api/contexts:crypto_contexts",
    ],
)

# =============================================================================
# FUTURE: Examples below depend on APIs not yet in scope.
# =============================================================================
# cc_binary(name = "encryption_example",   srcs = ["encryption_example.cpp"],   ...)
# cc_binary(name = "pqc_signing_example",  srcs = ["pqc_signing_example.cpp"],  ...)
# cc_binary(name = "certificate_example",  srcs = ["certificate_example.cpp"],  ...)
# cc_binary(name = "ephemeral_key_example",srcs = ["ephemeral_key_example.cpp"],...) # needs cipher context
# cc_binary(name = "cross_provider_example",srcs = ["cross_provider_example.cpp"],...)
# cc_binary(name = "key_lifecycle_complete",srcs = ["key_lifecycle_complete.cpp"],..)

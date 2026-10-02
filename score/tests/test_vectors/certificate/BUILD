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

# ---------------------------------------------------------------------------
# Per-folder filegroup targets.
#
# Test targets should depend on the smallest set they actually use:
#
#   :basic             — primary RSA-2048 PKI (cert management, trust store,
#                        cert parser, integration tests)
#   :algorithm_variety — one CA per key algorithm (slot handler variety tests)
#   :pki_chain         — three-level PKI for chain verification and OCSP tests
#
# The aggregating :certificate_test_vectors target is kept for backward
# compatibility; new test targets should prefer the specific sub-targets.
# ---------------------------------------------------------------------------

filegroup(
    name = "basic",
    srcs = glob(
        [
            "basic/**/*.pem",
            "basic/**/*.der",
            "basic/**/*.kv",
            "basic/**/*.json",
        ],
        allow_empty = True,
    ),
    visibility = ["//visibility:public"],
)

filegroup(
    name = "algorithm_variety",
    srcs = glob(
        [
            "algorithm_variety/**/*.pem",
            "algorithm_variety/**/*.kv",
            "algorithm_variety/**/*.json",
        ],
        allow_empty = True,
    ),
    visibility = ["//visibility:public"],
)

filegroup(
    name = "pki_chain",
    srcs = glob(
        [
            "pki_chain/**/*.pem",
            "pki_chain/**/*.der",
            "pki_chain/**/*.kv",
            "pki_chain/**/*.json",
            "pki_chain/**/*.conf",
        ],
        allow_empty = True,
    ),
    visibility = ["//visibility:public"],
)

# Aggregating target — backward compatible.
filegroup(
    name = "certificate_test_vectors",
    srcs = [
        ":basic",
        ":algorithm_variety",
        ":pki_chain",
    ],
    visibility = ["//visibility:public"],
)

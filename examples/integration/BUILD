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
    name = "hashing_client",
    srcs = ["hashing_client.cpp"],
    deps = [
        "@score_security_crypto//score/crypto/src/api:crypto_stack",
        "@score_security_crypto//score/crypto/src/api/config:context_configs",
        "@score_security_crypto//score/crypto/src/api/contexts:crypto_contexts",
    ],
)

sh_test(
    name = "hashing_smoke_test",
    srcs = ["run_hashing_smoke_test.sh"],
    args = [
        "$(rootpath @score_security_crypto//score/crypto/src/daemon:crypto_daemon)",
        "$(rootpath :hashing_client)",
        "$(rootpath @score_security_crypto//third_party/grpc:libgrpc_shared)",
        "$(rootpaths @score_security_crypto//third_party/openssl:openssl_so)",
    ],
    data = [
        ":hashing_client",
        "@score_security_crypto//score/crypto/src/daemon:crypto_daemon",
        "@score_security_crypto//third_party/grpc:libgrpc_shared",
        "@score_security_crypto//third_party/openssl:openssl_so",
    ],
    tags = ["exclusive"],
)

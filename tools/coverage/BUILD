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

load("@score_tooling//coverage:defs.bzl", "score_coverage_reporter", "score_coverage_scope")

# Coverage scope: the dependency-forest roots of every production
# (non-testonly, non-QNX-only) cc_library / rust_library under //score/... -
# the aspect walks transitive in-workspace deps, so everything below these
# roots is covered. Test scaffolding is excluded (see
# tools/coverage/scope_exclusions.txt); completeness is enforced by
# .github/tools/check_coverage_scope.sh as the first step of the coverage
# workflow.
score_coverage_scope(
    name = "coverage_scope",
    testonly = True,
    visibility = ["//visibility:private"],
    deps = [
        "//score/crypto/src/api:crypto_stack",
        "//score/crypto/src/api/future/common:future_common",
        "//score/crypto/src/backend:active_pkcs11_backend",
        "//score/crypto/src/backend:pkcs11_backend_defines",
        "//score/crypto/src/backend:score_backend_defines",
        "//score/crypto/src/backend/score_provider:backend",
        "//score/crypto/src/daemon/provider:provider_manager_factory",
        "//score/crypto/src/ipc/grpc_adapter:grpc_control_server",
        "//score/cryptoki:cryptoki_cdylib_wrapped",
        "//score/cryptoki:cryptoki_headers",
        "//score/cryptoki:cryptoki_lib",
        "//score/iav_primula",
    ],
)

score_coverage_reporter(
    name = "reporter_wrapper",
    testonly = True,
    coverage_scope = ":coverage_scope",
    llvm_cov = "@llvm_toolchain//:llvm-cov",
    llvm_cxxfilt = "@llvm_toolchain_llvm//:bin/llvm-cxxfilt",
    llvm_profdata = "@llvm_toolchain//:llvm-profdata",
    visibility = ["//visibility:public"],
)

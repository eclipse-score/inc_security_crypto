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

load("@score_docs_as_code//:docs.bzl", "docs")

docs(
    data = [
        "@score_process_description//:needs_json",
    ],
    source_dir = ".",
)

# bazel run //:shellcheck
alias(
    name = "shellcheck",
    actual = "@score_devcontainer//tools:shellcheck",
)

# bazel run //:actionlint
alias(
    name = "actionlint",
    actual = "@score_devcontainer//tools:actionlint",
)

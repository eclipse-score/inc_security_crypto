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
load("@rules_pkg//pkg:mappings.bzl", "pkg_attributes", "pkg_filegroup", "pkg_files")
load("@rules_pkg//pkg:tar.bzl", "pkg_tar")
load("@score_itf//:defs.bzl", "py_itf_test")

def integration_test(
        name,
        srcs,
        binaries,
        libraries = [],
        configs = [],
        file_pkgs = [],
        deps = [],
        **kwargs):
    """Creates two integration test targets (py_itf_test).

    1. py_itf_test target <name> runs the test script in a Docker environment.
       (supports parallel execution of multiple tests)
    2. py_itf_test target <name>_qemu runs the test script in a QEMU environment.
       (single execution only, therefore tagged with "exclusive")

    binaries, libraries, configs, and file_pkgs are packaged into a tarball
    named deployment.tar and made available to the test script.

    Both targets are tagged with "itf".

    Args:
        name: Name of the test target.
        srcs: Source files for the test target.
        binaries: List of binaries to be packaged into the deployment tarball (bin/).

        libraries: List of libraries to be packaged into the deployment tarball (lib/).
        configs: List of configuration files to be packaged into the deployment tarball (etc/).
        file_pkgs: List of additional pkg files to be packaged into the deployment tarball (share/).
        deps: List of dependencies for the test target.
        **kwargs: Additional keyword arguments to be passed to the py_itf_test rule.
    """

    pkg_files(
        name = "binaries",
        srcs = binaries,
        attributes = pkg_attributes(mode = "0755"),
        prefix = "bin",
    )

    pkg_files(
        name = "libraries",
        srcs = libraries,
        attributes = pkg_attributes(mode = "0755"),
        prefix = "lib",
    )

    pkg_files(
        name = "config",
        srcs = configs,
        prefix = "etc",
    )

    pkg_filegroup(
        name = "file_pkgs",
        srcs = file_pkgs,
        prefix = "share",
    )

    pkg_tar(
        name = "deployment",
        srcs = [
            ":binaries",
            ":libraries",
            ":config",
            ":file_pkgs",
        ],
    )

    marged_data = kwargs.pop("data", []) + [":deployment"]
    marged_tags = kwargs.pop("tags", []) + ["itf"]

    py_itf_test(
        name = name,
        srcs = srcs,
        deps = deps,
        args = [
            "--docker-image=ubuntu:24.04",
            "--log-level=INFO",
            "--keep-target",
        ],
        data = marged_data,
        plugins = ["@score_itf//score/itf/plugins:docker_plugin"],
        target_compatible_with = select({
            "@platforms//os:linux": [],
            "//conditions:default": ["@platforms//:incompatible"],
        }),
        tags = marged_tags,
        **kwargs
    )

    py_itf_test(
        name = "{}_qemu".format(name),
        srcs = srcs,
        deps = deps,
        args = [
            "--qemu-image=$(location //score/tests/environment/qemu:qnx_x86_64_ifs)",
            "--qemu-config=$(location //score/tests/environment/qemu:qemu_config.json)",
            "--log-level=INFO",
            "--keep-target",
        ],
        data = [
            "//score/tests/environment/qemu:qnx_x86_64_ifs",
            "//score/tests/environment/qemu:qemu_config.json",
        ] + marged_data,
        plugins = ["@score_itf//score/itf/plugins:qemu_plugin"],
        target_compatible_with = select({
            "@platforms//os:qnx": [],
            "//conditions:default": ["@platforms//:incompatible"],
        }),
        tags = [
            "exclusive",  # The QEMU plugin uses a hardcoded port so we can only run one test at a time.
        ] + marged_tags,
        **kwargs
    )

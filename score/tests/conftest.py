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

import logging
import os
from collections.abc import Generator
from pathlib import Path
from typing import cast

import pytest
from _pytest.mark import Mark

from score.tests.utility.process_runner import Target

logger = logging.getLogger(__name__)


def pytest_addoption(parser: pytest.Parser):
    parser.addoption(
        "--deployment-tar",
        required=True,
        help="Runfiles-relative path to the Bazel-generated deployment tarball.",
    )
    parser.addoption(
        "--pkcs11-backend-enabled",
        action="store_true",
        default=False,
        help="Enable PKCS#11-dependent integration-test setup.",
    )


def _absolute_path(rel_path: Path) -> Path:
    """Resolve a relative path to an absolute path, using RUNFILES_DIR if available.

    Uses current working directory as a fallback."""

    runfiles_dir = os.environ.get("RUNFILES_DIR")
    if runfiles_dir:
        runfile_path = Path(runfiles_dir) / rel_path
        if runfile_path.exists():
            return runfile_path

    # Fallback for local, non-Bazel execution
    local_path = Path.cwd() / rel_path
    if local_path.exists():
        return local_path

    raise FileNotFoundError(
        f"Could not find runfile path '{rel_path}' in RUNFILES_DIR, or current directory."
    )


@pytest.fixture(scope="session")
def target_os(target: Target) -> str:
    """Return the OS name of the target, as reported by `uname -s`."""
    _, output = target.execute("uname -s")
    return output.decode().strip()


@pytest.fixture(scope="class")
def install_dir(request: pytest.FixtureRequest) -> str:
    """Determine the installation directory for the test session.

    The default is derived from the Bazel target name, but can be overridden by
    applying the @pytest.mark.install_dir decorator to the test class.
    """

    # Convert Bazel target to a path-like string for install_dir, e.g. //foo/bar:baz -> foo/bar_baz
    bazel_target = os.environ.get("TEST_TARGET", "local")
    bazel_target_as_path = bazel_target.removeprefix("//").replace(":", "_")
    install_dir = f"/opt/{bazel_target_as_path}"

    # If the test class has an @pytest.mark.install_dir decorator, override the default install_dir.
    marker = cast(Mark | None, request.node.get_closest_marker("install_dir"))
    if marker:
        install_dir = cast(str, marker.args[0])

    return install_dir


@pytest.fixture(autouse=True, scope="class")
def deploy(
    target: Target, install_dir: str, request: pytest.FixtureRequest
) -> Generator[None, None, None]:
    """Deploy the deployment tarball content to the target and clean up afterward."""

    # Ensure install_dir not be a root folder, since we will be removing it after the test session.
    assert install_dir.count("/") >= 2, (
        f"install_dir must have at least two levels of directories: {install_dir}"
    )

    deployment_tar = cast(str, request.config.getoption("--deployment-tar"))
    host_tar = _absolute_path(Path(deployment_tar))
    tar_name = host_tar.name
    target_tar = f"{install_dir}/{tar_name}"
    logger.info(f"Deploying {tar_name} to {target_tar}.")

    assert host_tar.is_file(), f"File not found: {host_tar}"

    exit_code, output = target.execute(f"mkdir -p {install_dir}")
    assert exit_code == 0, (
        f"Failed to create install dir {install_dir}: {output.decode()}"
    )

    target.upload(str(host_tar), target_tar)

    exit_code, output = target.execute(f"tar -xf {target_tar} -C {install_dir}")
    assert exit_code == 0, f"Failed to extract {tar_name}: {output.decode()}"

    target.execute(f"rm -f {target_tar}")

    exit_code, output = target.execute(f"ls -lR {install_dir}")
    logger.info(f"Files in deployment location {install_dir}:\n{output.decode()}")

    yield

    logger.info(f"Cleaning up {install_dir} deployment directory.")
    exit_code, output = target.execute(f"rm -rf {install_dir}")
    if exit_code != 0:
        logger.error(f"Failed to clean up {install_dir}: {output.decode()}")

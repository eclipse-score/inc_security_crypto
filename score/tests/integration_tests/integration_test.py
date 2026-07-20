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

import os
from pathlib import Path
import tarfile
import io
import pytest
import logging
import time
from docker.models.containers import Container

# Reduce urllib3 logging noise
logging.getLogger("urllib3").setLevel(logging.WARNING)

# Get logger for this module
logger = logging.getLogger(__name__)


###################
# Utility functions
# Move to score_itf
###################
def _docker_upload(docker: Container, file_map: dict[Path, Path]):
    """
    Uploads files from file_map to given docker container
    docker: Docker container instance
    file_map: {Path(source): Path(target)}
    """
    cwd = Path(os.getcwd())

    # Create all target directories in the container
    target_dirs = set(str(tgt.parent) for tgt in file_map.values())
    for dir in target_dirs:
        exit_code, _ = docker.exec_run(f"mkdir -p {dir}")
        assert exit_code == 0, f"Failed to create directory {dir} in container"

    tar_stream = io.BytesIO()
    with tarfile.open(fileobj=tar_stream, mode="w") as tar:
        for src, tgt in file_map.items():
            abs_path = cwd / src
            assert abs_path.is_file(), f"File not found: {abs_path}"
            with abs_path.open("rb") as f:
                binary_data = f.read()
            tarinfo = tarfile.TarInfo(name=str(tgt).lstrip("/"))
            tarinfo.size = len(binary_data)
            tarinfo.mode = 0o755
            tar.addfile(tarinfo, io.BytesIO(binary_data))
    tar_stream.seek(0)

    # Upload to container root so all target paths are respected
    docker.put_archive("/", tar_stream)

    # Verify upload for each file
    for src, tgt in file_map.items():
        exit_code, output = docker.exec_run(f"test -x {tgt}")
        assert exit_code == 0, (
            f"Failed to upload {src} to {tgt}. Output: {output.decode()}"
        )
    logger.info(f"Successfully uploaded {src} to {tgt}.")


class ProcessHandler:
    """Helper class to manage a process inside the Docker container."""

    def __init__(
        self,
        docker: Container,
        binary: Path,
        log_file: Path,
        env: dict[str, str] | None = None,
    ):
        self.docker = docker
        self.binary = binary
        self.log_file = log_file
        self.pid = None
        self.env = env or {}

    def _clean_log(self):
        """Clean up the log file in the container."""
        exit_code, _ = self.docker.exec_run(f"rm -f {self.log_file}")
        return exit_code == 0

    def start(self) -> bool:
        """Start the process in the background with output redirected to log file."""
        self._clean_log()

        env_str = " ".join(f"{k}={v}" for k, v in self.env.items())
        base_env = "LD_LIBRARY_PATH=/opt/crypto/lib:$LD_LIBRARY_PATH"
        all_env = f"{base_env} {env_str}".strip()

        cmd = f"sh -c '{all_env} nohup {self.binary} > {self.log_file} 2>&1 &'"
        exit_code, output = self.docker.exec_run(cmd, detach=False)
        if exit_code != 0:
            logger.error(f"Failed to start process: {output.decode()}")
            return False

        # Get the PID of the started process
        time.sleep(0.5)  # Give it a moment to start
        exit_code, output = self.docker.exec_run(f"pgrep -f '{self.binary}'")
        if exit_code != 0:
            # Process not found, check the log for errors
            log_contents = self.get_log_contents()
            logger.error(
                f"Failed to find process after start. Log contents:\n{log_contents}"
            )
            return False

        self.pid = output.decode().strip()
        logger.info(f"Started process '{self.binary}' with PID {self.pid}")
        return True

    def terminate(self, timeout: int = 3) -> bool:
        """Terminate the process with SIGTERM and wait for it to exit."""
        assert self.pid is not None, "Process not started"
        exit_code, output = self.docker.exec_run(f"sh -c 'kill -TERM {self.pid}'")
        logger.info(
            f"SIGTERM command exit_code={exit_code}, output='{output.decode()}'"
        )

        # Wait for the process to terminate
        for i in range(timeout * 10):  # Check every 100ms
            exit_code, _ = self.docker.exec_run(f"pgrep -f '{self.binary}'")
            if exit_code != 0:
                logger.info(f"Process '{self.binary}' terminated within {i * 0.1:.1f}s")
                return True
            time.sleep(0.1)
        else:
            # Force kill if still running
            self.docker.exec_run(f"pkill -9 -f '{self.binary}'")
            logger.info(f"Had to force kill process '{self.binary}' with SIGKILL")
            return False

    def get_log_contents(self) -> str:
        """Retrieve the contents of the log file."""
        exit_code, output = self.docker.exec_run(f"cat {self.log_file}")
        if exit_code != 0:
            logger.error(f"Failed to read log file: {output.decode()}")
            return ""
        return output.decode()


############
# Test cases
############
class TestCryptoDaemon:
    """Test suite for crypto_daemon Docker container."""

    # SoftHSM token settings shared by setup_container and daemon fixtures.
    SOFTHSM_TOKEN_DIR = "/tmp/softhsm_tokens"
    SOFTHSM_CONF_PATH = "/tmp/softhsm2.conf"
    SOFTHSM_TOKEN_LABEL = "SoftHSM"
    SOFTHSM_SO_PIN = "12345678"
    SOFTHSM_USER_PIN = "1234"

    # Crypto config
    CRYPTO_CONFIG_PATH = (
        "/opt/crypto/tests/test_vectors/config/integration_test_config.bin"
    )

    @pytest.fixture(autouse=True)
    def setup_container(self, docker):
        """Upload binaries/libraries and initialise a SoftHSM token via the
        init_softhsm_token helper binary (no package installation required)."""

        logger.info("Setup container: uploading files")
        _docker_upload(
            docker,
            {
                Path("score/crypto/daemon/crypto_daemon"): Path(
                    "/opt/crypto/bin/crypto_daemon"
                ),
                Path("tests/integration_tests/control_client_app"): Path(
                    "/opt/crypto/bin/control_client_app"
                ),
                Path("tests/integration_tests/init_softhsm_token"): Path(
                    "/opt/crypto/bin/init_softhsm_token"
                ),
                Path("tests/integration_tests/score_api_hash_example"): Path(
                    "/opt/crypto/bin/score_api_hash_example"
                ),
                Path("tests/integration_tests/score_api_mac_example"): Path(
                    "/opt/crypto/bin/score_api_mac_example"
                ),
                Path("tests/integration_tests/score_demo"): Path(
                    "/opt/crypto/bin/score_demo"
                ),
                Path("third_party/grpc/libgrpc++.so.1"): Path(
                    "/opt/crypto/lib/libgrpc++.so.1"
                ),
                Path("third_party/openssl/libopenssl.so.3"): Path(
                    "/opt/crypto/lib/libopenssl.so.3"
                ),
                Path(
                    "third_party/soft_hsm/soft_hsm_cmake/lib/softhsm/libsofthsm2.so"
                ): Path("/opt/crypto/lib/libsofthsm2.so"),
                Path("tests/test_vectors/config/integration_test_config.bin"): Path(
                    self.CRYPTO_CONFIG_PATH
                ),
                Path("tests/test_vectors/hash/input_hello_world.bin"): Path(
                    "/opt/crypto/tests/test_vectors/hash/input_hello_world.bin"
                ),
                Path("tests/test_vectors/hash/sha256_hello_world.bin"): Path(
                    "/opt/crypto/tests/test_vectors/hash/sha256_hello_world.bin"
                ),
                Path("tests/test_vectors/hash/input_complete_data.bin"): Path(
                    "/opt/crypto/tests/test_vectors/hash/input_complete_data.bin"
                ),
                Path("tests/test_vectors/hash/sha256_complete_data.bin"): Path(
                    "/opt/crypto/tests/test_vectors/hash/sha256_complete_data.bin"
                ),
                Path("tests/test_vectors/mac/input_hello_world.bin"): Path(
                    "/opt/crypto/tests/test_vectors/mac/input_hello_world.bin"
                ),
                Path("tests/test_vectors/mac/input_complete_data.bin"): Path(
                    "/opt/crypto/tests/test_vectors/mac/input_complete_data.bin"
                ),
                Path("tests/test_vectors/mac/hmac_sha256_hello_world.bin"): Path(
                    "/opt/crypto/tests/test_vectors/mac/hmac_sha256_hello_world.bin"
                ),
                Path("tests/test_vectors/mac/hmac_sha256_complete_data.bin"): Path(
                    "/opt/crypto/tests/test_vectors/mac/hmac_sha256_complete_data.bin"
                ),
                Path("tests/test_vectors/mac/key_aes_256.key"): Path(
                    "/opt/crypto/tests/test_vectors/mac/key_aes_256.key"
                ),
                Path("tests/test_vectors/config/integration_openssl_hmac.kv"): Path(
                    "/opt/crypto/deploy/integration_openssl_hmac.kv"
                ),
                Path("tests/test_vectors/config/integration_softhsm_hmac.kv"): Path(
                    "/opt/crypto/deploy/integration_softhsm_hmac.kv"
                ),
                Path("tests/config/logging.json"): Path(
                    "/opt/crypto/config/logging.json"
                ),
            },
        )

        # Initialise SoftHSM token using the purpose-built helper binary.
        # Import the MAC test key so that KeySlotMacTest can load it from the
        # SoftHSM token at integration-test time.
        logger.info("Initialising SoftHSM token via init_softhsm_token")
        exit_code, output = docker.exec_run(
            f"sh -c 'LD_LIBRARY_PATH=/opt/crypto/lib:$LD_LIBRARY_PATH "
            f"/opt/crypto/bin/init_softhsm_token"
            f" --token-dir {self.SOFTHSM_TOKEN_DIR}"
            f" --config-path {self.SOFTHSM_CONF_PATH}"
            f" --token-label {self.SOFTHSM_TOKEN_LABEL}"
            f" --so-pin {self.SOFTHSM_SO_PIN}"
            f" --user-pin {self.SOFTHSM_USER_PIN}"
            f" --import-key-file /opt/crypto/tests/test_vectors/mac/key_aes_256.key"
            f" --import-key-label integration_test_hmac'"
        )
        assert exit_code == 0, (
            f"init_softhsm_token failed (exit {exit_code}):\n{output.decode()}"
        )
        logger.info(f"init_softhsm_token output: {output.decode().strip()}")

    @pytest.fixture
    def daemon(self, docker):
        """Start the crypto daemon, then teardown after test."""
        daemon = ProcessHandler(
            docker,
            Path("/opt/crypto/bin/crypto_daemon"),
            Path("/tmp/crypto_daemon.log"),
            env={
                "SOFTHSM2_CONF": self.SOFTHSM_CONF_PATH,
                "CRYPTO_CONFIG_FILE": self.CRYPTO_CONFIG_PATH,
                "MW_LOG_CONFIG_FILE": "/opt/crypto/config/logging.json",
            },
        )
        assert daemon.start(), "Failed to start crypto_daemon"

        yield daemon

        assert daemon.terminate(timeout=3), "crypto_daemon did not terminate gracefully"
        log_contents = daemon.get_log_contents()
        logger.info(f"crypto_daemon log contents:\n{log_contents}")

    def test_daemon_control_socket_creation(self, docker, daemon):
        """Test that crypto_daemon creates socket and handles SIGTERM."""
        # Wait for the Unix domain socket to be created (max 5 seconds)
        socket_path = "/tmp/crypto_daemon.sock"
        max_wait = 5
        socket_found = False

        for i in range(max_wait * 10):  # Check every 100ms
            exit_code, output = docker.exec_run(f"test -S {socket_path}")
            if exit_code == 0:
                socket_found = True
                logger.info(
                    f"Unix domain socket {socket_path} created within {i * 0.1:.1f}s"
                )
                break
            time.sleep(0.1)

        assert socket_found, (
            f"Unix domain socket {socket_path} was not created within {max_wait} seconds"
        )

    def test_control_communication_basic(self, docker, daemon):
        """Test basic communication of the control plane daemon."""

        exit_code, output = docker.exec_run(
            "sh -c 'LD_LIBRARY_PATH=/opt/crypto/lib:$LD_LIBRARY_PATH /opt/crypto/bin/control_client_app'"
        )
        logger.info(
            f"control_client_app exit_code={exit_code}, output:\n{output.decode()}"
        )
        assert exit_code == 0, (
            f"control_client_app failed with exit code {exit_code}. Output: {output.decode()}"
        )

    def test_score_api_hash_example(self, docker, daemon):
        """Test SCORE HASH API."""

        exit_code, output = docker.exec_run(
            "sh -c 'LD_LIBRARY_PATH=/opt/crypto/lib:$LD_LIBRARY_PATH /opt/crypto/bin/score_api_hash_example'"
        )
        logger.info(
            f"test_score_api_hash_example exit_code={exit_code}, output:\n{output.decode()}"
        )
        assert exit_code == 0, (
            f"test_score_api_hash_example failed with exit code {exit_code}. Output: {output.decode()}"
        )

    def test_score_api_mac_example(self, docker, daemon):
        """Test SCORE KeyGeneration and MAC API."""

        exit_code, output = docker.exec_run(
            "sh -c 'LD_LIBRARY_PATH=/opt/crypto/lib:$LD_LIBRARY_PATH /opt/crypto/bin/score_api_mac_example'"
        )
        logger.info(
            f"test_score_api_mac_example exit_code={exit_code}, output:\n{output.decode()}"
        )
        assert exit_code == 0, (
            f"test_score_api_mac_example failed with exit code {exit_code}. Output: {output.decode()}"
        )

    def test_score_demo(self, docker, daemon):
        """Test SCORE Demo."""

        exit_code, output = docker.exec_run(
            "sh -c 'LD_LIBRARY_PATH=/opt/crypto/lib:$LD_LIBRARY_PATH /opt/crypto/bin/score_demo'"
        )
        logger.info(
            f"test_score_demo exit_code={exit_code}, output:\n{output.decode()}"
        )
        assert exit_code == 0, (
            f"test_score_demo failed with exit code {exit_code}. Output: {output.decode()}"
        )

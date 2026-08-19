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

from pathlib import Path
import pytest
import logging
import time

from score.tests.utility.process_runner import ProcessRunner, run_test_app

# Reduce urllib3 logging noise
logging.getLogger("urllib3").setLevel(logging.WARNING)

# Get logger for this module
logger = logging.getLogger(__name__)


############
# Test cases
############
@pytest.mark.install_dir("/opt/crypto")
class TestCryptoDaemon:
    """Test suite for crypto_daemon Docker container."""

    # Shared between softhsm_token and daemon fixtures.
    SOFTHSM_CONF_PATH = "/tmp/softhsm2.conf"

    @pytest.fixture(autouse=True, scope="class")
    def softhsm_token(self, request, target, target_os, deploy, install_dir):
        if not request.config.getoption("--pkcs11-backend-enabled"):
            yield
            return

        token_dir = Path(f"{install_dir}/share/tmp_token")
        token_label = "SoftHSM"
        so_pin = "12345678"
        user_pin = "1234"

        logger.info("Initialising SoftHSM token via init_pkcs11_token")
        handler = ProcessRunner(
            target,
            Path(f"{install_dir}/bin/init_pkcs11_token"),
            Path("/tmp/init_pkcs11_token.log"),
            target_os=target_os,
            env={"LD_LIBRARY_PATH": f"{install_dir}/lib"},
            args=[
                "--token-dir",
                str(token_dir),
                "--config-path",
                self.SOFTHSM_CONF_PATH,
                "--token-label",
                token_label,
                "--so-pin",
                so_pin,
                "--user-pin",
                user_pin,
                "--import-key-file",
                f"{install_dir}/share/test_vectors/mac/key_aes_256.key",
                "--import-key-label",
                "integration_test_hmac",
            ],
        )
        exit_code = handler.run()
        log = handler.get_log_contents()
        if exit_code != 0:
            logger.error(f"init_pkcs11_token failed (exit code {exit_code}):\n{log}")
            assert False, f"init_pkcs11_token failed (exit code {exit_code})"
        else:
            logger.info(f"init_pkcs11_token output:\n{log}")

        yield

        logger.info(f"Cleaning up {token_dir} SoftHSM token directory.")
        if token_dir.exists():
            for item in token_dir.iterdir():
                item.unlink()
            token_dir.rmdir()

    @pytest.fixture(scope="class")
    def daemon(self, target, target_os, install_dir):
        """Start the crypto daemon, then teardown after test."""
        daemon: ProcessRunner = ProcessRunner(
            target,
            Path(f"{install_dir}/bin/crypto_daemon"),
            Path("/tmp/crypto_daemon.log"),
            target_os=target_os,
            env={
                "SOFTHSM2_CONF": self.SOFTHSM_CONF_PATH,
                "CRYPTO_CONFIG_FILE": f"{install_dir}/etc/integration_test_config.bin",
                "MW_LOG_CONFIG_FILE": f"{install_dir}/etc/logging.json",
                "LD_LIBRARY_PATH": f"{install_dir}/lib:$LD_LIBRARY_PATH",
            },
        )
        assert daemon.start(), "Failed to start crypto_daemon"

        yield daemon

        assert daemon.terminate(timeout=3), "crypto_daemon did not terminate gracefully"
        log_contents = daemon.get_log_contents()
        logger.info(f"crypto_daemon log contents:\n{log_contents}")

    def test_daemon_control_socket_creation(
        self, target, daemon, install_dir, target_os
    ):
        """Test that crypto_daemon creates socket and handles SIGTERM."""
        tmp_dir = "/opt" if target_os == "QNX" else "/tmp"
        socket_path = f"{tmp_dir}/crypto_daemon.sock"
        max_wait = 5
        socket_found = False

        for i in range(max_wait * 10):  # Check every 100ms
            exit_code, output = target.execute(f"test -S {socket_path}")
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

    def test_score_api_hash(self, target, target_os, daemon, install_dir):
        """Test SCORE HASH API."""
        run_test_app(
            target,
            target_os,
            Path(f"{install_dir}/bin/score_api_hash_test"),
            env={
                "LD_LIBRARY_PATH": f"{install_dir}/lib",
                "TEST_VECTORS_DIR": f"{install_dir}/share/test_vectors",
            },
        )

    def test_score_api_mac(self, target, target_os, daemon, install_dir):
        """Test SCORE KeyGeneration and MAC API."""
        run_test_app(
            target,
            target_os,
            Path(f"{install_dir}/bin/score_api_mac_test"),
            env={
                "LD_LIBRARY_PATH": f"{install_dir}/lib",
                "TEST_VECTORS_DIR": f"{install_dir}/share/test_vectors",
            },
        )

    def test_hash_performance_test(self, target, target_os, daemon, install_dir):
        """Test concurrent and sequential hash operations."""
        run_test_app(
            target,
            target_os,
            Path(f"{install_dir}/bin/hash_performance_test"),
            env={
                "LD_LIBRARY_PATH": f"{install_dir}/lib",
                "TEST_VECTORS_DIR": f"{install_dir}/share/test_vectors",
            },
        )

    def test_score_demo(self, target, target_os, daemon, install_dir):
        """Test SCORE Demo."""
        run_test_app(
            target,
            target_os,
            Path(f"{install_dir}/bin/score_demo"),
            env={
                "LD_LIBRARY_PATH": f"{install_dir}/lib",
                "TEST_VECTORS_DIR": f"{install_dir}/share/test_vectors",
            },
        )

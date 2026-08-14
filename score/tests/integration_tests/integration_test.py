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

from score.tests.utility.process_runner import ProcessRunner

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
    def softhsm_token(self, target, deploy, install_dir, make_process):
        token_dir = Path(f"{install_dir}/share/tmp_token")
        token_label = "SoftHSM"
        so_pin = "12345678"
        user_pin = "1234"

        logger.info("Initialising SoftHSM token via init_pkcs11_token")
        handler = make_process(
            Path(f"{install_dir}/bin/init_pkcs11_token"),
            Path("/tmp/init_pkcs11_token.log"),
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
    def daemon(self, target, make_process, install_dir):
        """Start the crypto daemon, then teardown after test."""
        daemon: ProcessRunner = make_process(
            Path(f"{install_dir}/bin/crypto_daemon"),
            Path("/tmp/crypto_daemon.log"),
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

    def test_score_api_hash_example(self, target, daemon, install_dir, make_process):
        """Test SCORE HASH API."""
        test_app_name = "score_api_hash_example"
        test_app: ProcessRunner = make_process(
            Path(f"{install_dir}/bin/{test_app_name}"),
            Path(f"/tmp/{test_app_name}.log"),
            env={
                "LD_LIBRARY_PATH": f"{install_dir}/lib",
                "TEST_VECTORS_DIR": f"{install_dir}/share/test_vectors",
            },
        )
        exit_code = test_app.run()
        log = test_app.get_log_contents()
        logger.info(f"{test_app_name} output:\n{log}")
        assert exit_code == 0, f"{test_app_name} failed with exit code {exit_code}."

    def test_score_api_mac_example(self, target, daemon, install_dir, make_process):
        """Test SCORE KeyGeneration and MAC API."""
        test_app_name = "score_api_mac_example"
        test_app: ProcessRunner = make_process(
            Path(f"{install_dir}/bin/{test_app_name}"),
            Path(f"/tmp/{test_app_name}.log"),
            env={
                "LD_LIBRARY_PATH": f"{install_dir}/lib",
                "TEST_VECTORS_DIR": f"{install_dir}/share/test_vectors",
            },
        )
        exit_code = test_app.run()
        log = test_app.get_log_contents()
        logger.info(f"{test_app_name} output:\n{log}")
        assert exit_code == 0, f"{test_app_name} failed with exit code {exit_code}."

    def test_hash_performance_test(self, target, daemon, install_dir, make_process):
        """Test concurrent and sequential hash operations."""
        test_app_name = "hash_performance_test"
        test_app: ProcessRunner = make_process(
            Path(f"{install_dir}/bin/{test_app_name}"),
            Path(f"/tmp/{test_app_name}.log"),
            env={
                "LD_LIBRARY_PATH": f"{install_dir}/lib",
                "TEST_VECTORS_DIR": f"{install_dir}/share/test_vectors",
            },
        )
        exit_code = test_app.run()
        log = test_app.get_log_contents()
        logger.info(f"{test_app_name} output:\n{log}")
        assert exit_code == 0, f"{test_app_name} failed with exit code {exit_code}."

    def test_score_demo(self, target, daemon, install_dir, make_process):
        """Test SCORE Demo."""
        test_app_name = "score_demo"
        test_app = make_process(
            Path(f"{install_dir}/bin/{test_app_name}"),
            Path(f"/tmp/{test_app_name}.log"),
            env={
                "LD_LIBRARY_PATH": f"{install_dir}/lib",
                "TEST_VECTORS_DIR": f"{install_dir}/share/test_vectors",
            },
        )
        exit_code = test_app.run()
        log = test_app.get_log_contents()
        logger.info(f"{test_app_name} output:\n{log}")
        assert exit_code == 0, f"{test_app_name} failed with exit code {exit_code}."

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
import time
from pathlib import Path

import pytest

from score.tests.utility.process_runner import ProcessRunner, Target, run_test_app

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

    # Unified token storage directory inside the container.
    TOKEN_DIR = "/opt/crypto/share/tmp_token"
    SOFTHSM_CONF_PATH = f"{TOKEN_DIR}/softhsm2.conf"
    CRYPTOKI_STORE_PATH = f"{TOKEN_DIR}/token.json"

    @pytest.fixture(autouse=True, scope="class")
    def init_pkcs11_token(self, request: pytest.FixtureRequest, target: Target, target_os: str, deploy: None, install_dir: str):
        if not request.config.getoption("--pkcs11-backend-enabled"):
            yield
            return

        token_label = "PKCS11_TOKEN"
        so_pin = "12345678"
        user_pin = "1234"

        # Prepare unified token storage directory and SoftHSM configuration file
        exit_code, output = target.execute(f"mkdir -p {self.TOKEN_DIR}")
        assert exit_code == 0, f"Failed to create token directory {self.TOKEN_DIR}: {output.decode()}"

        softhsm_conf = (
            f"directories.tokendir = {self.TOKEN_DIR}\n"
            f"objectstore.backend = file\n"
            f"log.level = INFO\n"
        )
        exit_code, output = target.execute(f"printf '{softhsm_conf}' > {self.SOFTHSM_CONF_PATH}")
        assert exit_code == 0, f"Failed to write SoftHSM config {self.SOFTHSM_CONF_PATH}: {output.decode()}"

        logger.info("Initialising PKCS#11 token via init_pkcs11_token")
        handler = ProcessRunner(
            target,
            Path(f"{install_dir}/bin/init_pkcs11_token"),
            Path("/tmp/init_pkcs11_token.log"),
            target_os=target_os,
            env={
                "LD_LIBRARY_PATH": f"{install_dir}/lib",
                "SOFTHSM2_CONF": self.SOFTHSM_CONF_PATH,
                "CRYPTOKI_STORE": self.CRYPTOKI_STORE_PATH,
            },
            args=[
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
        assert exit_code == 0, (
            f"init_pkcs11_token failed (exit code {exit_code}):\n{log}"
        )
        logger.info(f"init_pkcs11_token output:\n{log}")

        yield

        logger.info(f"Cleaning up {self.TOKEN_DIR} pkcs11 token directory.")
        exit_code, output = target.execute(f"rm -rf {self.TOKEN_DIR}")
        if exit_code != 0:
            logger.error(
                f"Failed to clean up {self.TOKEN_DIR} pkcs11 token directory: "
                f"{output.decode()}"
            )

    @pytest.fixture(autouse=True, scope="class")
    def daemon(
        self,
        target: Target,
        target_os: str,
        install_dir: str,
        init_pkcs11_token: None,
    ):
        """Start the crypto daemon, then teardown after test."""
        daemon: ProcessRunner = ProcessRunner(
            target,
            Path(f"{install_dir}/bin/crypto_daemon"),
            Path("/tmp/crypto_daemon.log"),
            target_os=target_os,
            env={
                "SOFTHSM2_CONF": self.SOFTHSM_CONF_PATH,
                "CRYPTOKI_STORE": self.CRYPTOKI_STORE_PATH,
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

    def test_score_api_hash(self, target: Target, target_os: str, install_dir: str):
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

    def test_score_api_mac(self, target: Target, target_os: str, install_dir: str):
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

    def test_score_api_cipher(
        self, target: Target, target_os: str, install_dir: str, openssl_backend: None
    ):
        """Test SCORE symmetric encryption / decryption API."""
        run_test_app(
            target,
            target_os,
            Path(f"{install_dir}/bin/score_api_cipher_test"),
            env={
                "LD_LIBRARY_PATH": f"{install_dir}/lib",
                "TEST_VECTORS_DIR": f"{install_dir}/share/test_vectors",
            },
        )

    def test_score_api_random(
        self, target: Target, target_os: str, install_dir: str, openssl_backend: None
    ):
        """Test SCORE random number generation API."""
        run_test_app(
            target,
            target_os,
            Path(f"{install_dir}/bin/score_api_random_test"),
            env={
                "LD_LIBRARY_PATH": f"{install_dir}/lib",
                "TEST_VECTORS_DIR": f"{install_dir}/share/test_vectors",
            },
        )

    def test_score_api_ecdsa(
        self, target: Target, target_os: str, install_dir: str, openssl_backend: None
    ):
        """Test SCORE ECDSA key generation, signing and verification API."""
        run_test_app(
            target,
            target_os,
            Path(f"{install_dir}/bin/score_api_ecdsa_test"),
            env={
                "LD_LIBRARY_PATH": f"{install_dir}/lib",
                "TEST_VECTORS_DIR": f"{install_dir}/share/test_vectors",
            },
        )

    def _run_score_api_signature(self, target: Target, target_os: str, install_dir: str, gtest_filter: str):
        run_test_app(
            target,
            target_os,
            Path(f"{install_dir}/bin/score_api_signature_test"),
            env={
                "LD_LIBRARY_PATH": f"{install_dir}/lib",
                "TEST_VECTORS_DIR": f"{install_dir}/share/test_vectors",
            },
            args=[f"--gtest_filter={gtest_filter}"],
        )

    def test_score_api_signature_streaming(
        self, target: Target, target_os: str, install_dir: str, openssl_backend: None
    ):
        """Test streaming ECDSA/RSA-PSS and Ed25519 streaming rejection."""
        self._run_score_api_signature(
            target, target_os, install_dir, "*SignAndVerifyStreaming*:*RejectsStreaming*"
        )

    def test_score_api_signature_ss(
        self, target: Target, target_os: str, install_dir: str, openssl_backend: None
    ):
        """Test SingleShot ECDSA, RSA-PSS and Ed25519 signing API."""
        self._run_score_api_signature(target, target_os, install_dir, "*SignAndVerifySS*")

    def test_score_api_key_permissions(self, target: Target, target_os: str, install_dir: str):
        """Test SCORE key operation permission enforcement at context creation."""
        run_test_app(
            target,
            target_os,
            Path(f"{install_dir}/bin/score_api_key_permissions_test"),
            env={
                "LD_LIBRARY_PATH": f"{install_dir}/lib",
                "TEST_VECTORS_DIR": f"{install_dir}/share/test_vectors",
            },
        )

    def test_score_api_key_import_export(
        self, target: Target, target_os: str, install_dir: str, openssl_backend: None
    ):
        """Test SCORE raw EC public-key import and export end to end."""
        run_test_app(
            target,
            target_os,
            Path(f"{install_dir}/bin/score_api_key_import_export_test"),
            env={
                "LD_LIBRARY_PATH": f"{install_dir}/lib",
                "TEST_VECTORS_DIR": f"{install_dir}/share/test_vectors",
            },
        )

    def test_hash_performance_test(self, target: Target, target_os: str, install_dir: str):
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

    def test_score_demo(self, target: Target, target_os: str, install_dir: str):
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

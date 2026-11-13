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

    # Shared between init_pkcs11_token and daemon fixtures.
    SOFTHSM_CONF_PATH = "/tmp/softhsm2.conf"

    @pytest.fixture(autouse=True, scope="class")
    def init_pkcs11_token(self, request: pytest.FixtureRequest, target: Target, target_os: str, deploy: None, install_dir: str):
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
        assert exit_code == 0, (
            f"init_pkcs11_token failed (exit code {exit_code}):\n{log}"
        )
        logger.info(f"init_pkcs11_token output:\n{log}")

        yield

        logger.info(f"Cleaning up {token_dir} pkcs11 token directory.")
        exit_code, output = target.execute(f"rm -rf {token_dir}")
        if exit_code != 0:
            logger.error(
                f"Failed to clean up {token_dir} pkcs11 token directory: "
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

    def test_daemon_control_socket_creation(self, target: Target, target_os: str):
        """Test that crypto_daemon creates socket and handles SIGTERM."""
        tmp_dir = "/opt" if target_os == "QNX" else "/tmp"
        socket_path = f"{tmp_dir}/crypto_daemon.sock"
        max_wait = 5
        socket_found = False

        for i in range(max_wait * 10):  # Check every 100ms
            exit_code, _output = target.execute(f"test -S {socket_path}")
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

    # Source: fea_um_crypto_1 ancestor 5e8664e37, same harness method.
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

    # Harness hook from fea_um_crypto_1 1f4b0daa5919e9d354b53a565e7febbd28a34546;
    # the C++ tests are from 5e8664e37, whose peer process needs /proc/self/exe.
    def test_score_api_csr(
        self, target: Target, target_os: str, install_dir: str, openssl_backend: None
    ):
        """Run generated-key CSR coverage over the real daemon connection."""
        if target_os != "Linux":
            pytest.skip("CSR peer-process coverage requires Linux /proc/self/exe")

        self.test_daemon_control_socket_creation(target, target_os)
        socket_dir = "/opt" if target_os == "QNX" else "/tmp"
        run_test_app(
            target,
            target_os,
            Path(f"{install_dir}/bin/score_api_csr_test"),
            env={
                "LD_LIBRARY_PATH": f"{install_dir}/lib",
                "CSR_TEST_ENDPOINT": f"unix://{socket_dir}/crypto_daemon.sock",
            },
        )

    def test_score_api_csr_subject_key_identifier_hash(
        self, target: Target, target_os: str, install_dir: str, openssl_backend: None
    ):
        """Exercise the public-SPKI DER encoding fallback over gRPC/SHM."""
        if target_os != "Linux":
            pytest.skip("CSR transport integration coverage currently targets Linux")

        self.test_daemon_control_socket_creation(target, target_os)
        run_test_app(
            target,
            target_os,
            Path(f"{install_dir}/bin/score_api_csr_test"),
            env={
                "LD_LIBRARY_PATH": f"{install_dir}/lib",
                "CSR_TEST_ENDPOINT": "unix:///tmp/crypto_daemon.sock",
            },
            args=[
                "--gtest_filter=CsrTransport."
                "SubjectKeyIdentifierHashUsesBoundDaemonPublicKeyAfterKeyHandleRelease"
            ],
        )

    def test_score_api_key_persistence(
        self,
        target: Target,
        target_os: str,
        install_dir: str,
        openssl_backend: None,
        daemon: ProcessRunner,
    ):
        """Reload the same generated key after graceful and forced daemon restarts.

        The phased binary extends fea_um_crypto_1's persistent-slot enrollment
        flow. Killing a daemon does not power off storage: this is explicitly
        process-restart coverage, not an ECU power-loss durability claim.
        """
        if target_os != "Linux":
            pytest.skip("Forced daemon-restart coverage uses Linux pkill")

        self.test_daemon_control_socket_creation(target, target_os)
        state_dir = f"{install_dir}/etc/csr-slots"
        exit_code, output = target.execute(
            f"mkdir -p {state_dir} && chmod 700 {state_dir} && "
            f"test ! -e {state_dir}/device_key.der && "
            f"test ! -e {state_dir}/reference.csr.der"
        )
        assert exit_code == 0, (
            "Persistence test requires an empty, private test slot directory; "
            f"existing key material is never removed: {output.decode()}"
        )

        binary = Path(f"{install_dir}/bin/score_api_key_persistence_test")
        env = {
            "LD_LIBRARY_PATH": f"{install_dir}/lib",
            "CSR_TEST_ENDPOINT": "unix:///tmp/crypto_daemon.sock",
            "CSR_TEST_REFERENCE_CSR": f"{state_dir}/reference.csr.der",
        }
        run_test_app(
            target,
            target_os,
            binary,
            env=env | {
                "GTEST_FILTER": "KeyPersistenceIntegration.GenerateAndPersistDeviceKey",
            },
        )
        exit_code, output = target.execute(
            f"test -s {state_dir}/device_key.der && "
            f"test -s {state_dir}/reference.csr.der"
        )
        assert exit_code == 0, f"Key/reference CSR was not stored: {output.decode()}"

        for restart in ("graceful", "forced"):
            exit_code, before_pid = target.execute("pgrep -x crypto_daemon")
            assert exit_code == 0 and len(before_pid.splitlines()) == 1, (
                "Expected exactly one running test daemon before restart"
            )
            if restart == "graceful":
                assert daemon.terminate(timeout=3), "Daemon did not terminate gracefully"
            else:
                # No sync or storage reset: exercise loss of all daemon memory,
                # without pretending that the operating system lost power.
                exit_code, output = target.execute("pkill -KILL -x crypto_daemon")
                assert exit_code == 0, f"Failed to kill daemon: {output.decode()}"

            logger.info("Daemon log before %s restart:\n%s", restart, daemon.get_log_contents())
            assert daemon.start(), f"Daemon failed to start after {restart} shutdown"
            exit_code, after_pid = target.execute("pgrep -x crypto_daemon")
            assert exit_code == 0 and len(after_pid.splitlines()) == 1, (
                "Expected exactly one running test daemon after restart"
            )
            assert after_pid.strip() != before_pid.strip(), "Daemon process did not change"
            self.test_daemon_control_socket_creation(target, target_os)
            run_test_app(
                target,
                target_os,
                binary,
                env=env | {
                    "GTEST_FILTER": "KeyPersistenceIntegration.ReloadPersistedDeviceKeyAndSignCsr",
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

    def test_score_cert_management_integration(
        self, request: pytest.FixtureRequest, target: Target, target_os: str, install_dir: str
    ):
        """Run the focused certificate-management GTest binary."""
        if not request.config.getoption("--openssl-backend-enabled"):
            pytest.skip("Certificate integration tests require the OpenSSL backend")

        run_test_app(
            target,
            target_os,
            Path(f"{install_dir}/bin/score_cert_management_integration_test"),
            env={
                "LD_LIBRARY_PATH": f"{install_dir}/lib",
                "TEST_VECTORS_DIR": f"{install_dir}/share/test_vectors",
            },
        )

    def test_score_cert_management_write_access_control(
        self, request: pytest.FixtureRequest, target: Target, target_os: str, install_dir: str
    ):
        """Run the denied certificate-slot write test as UID 1000."""
        if not request.config.getoption("--openssl-backend-enabled"):
            pytest.skip("Certificate integration tests require the OpenSSL backend")
        if target_os == "QNX":
            pytest.skip("The QNX integration target has no portable user-switch command")

        command = (
            "setpriv --reuid=1000 --regid=1000 --clear-groups "
            f"env LD_LIBRARY_PATH={install_dir}/lib "
            f"TEST_VECTORS_DIR={install_dir}/share/test_vectors "
            f"{install_dir}/bin/score_cert_management_integration_test "
            "--gtest_color=no "
            "--gtest_filter=CertificateManagementIntegrationTest.RejectsCertificateSlotWriteWithoutPermission"
        )
        exit_code, output = target.execute(command)
        output_str = output.decode()
        logger.info(f"test_score_cert_management_write_access_control output:\n{output_str}")
        assert exit_code == 0, (
            "score_cert_management write-access test failed with exit code "
            f"{exit_code}. Output:\n{output_str}"
        )

    def test_score_cert_verification_integration(
        self, request: pytest.FixtureRequest, target: Target, target_os: str, install_dir: str
    ):
        """Run practical multi-anchor, chain-policy, and CRL verification tests."""
        if not request.config.getoption("--openssl-backend-enabled"):
            pytest.skip("Certificate integration tests require the OpenSSL backend")

        run_test_app(
            target,
            target_os,
            Path(f"{install_dir}/bin/score_cert_verification_integration_test"),
            env={
                "LD_LIBRARY_PATH": f"{install_dir}/lib",
                "TEST_VECTORS_DIR": f"{install_dir}/share/test_vectors",
            },
        )

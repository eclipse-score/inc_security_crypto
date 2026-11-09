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

from concurrent.futures import ThreadPoolExecutor
import time
import uuid
import logging
from pathlib import Path

import pytest

from score.tests.utility.process_runner import ProcessRunner, Target

# Reduce urllib3 logging noise
logging.getLogger("urllib3").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

@pytest.mark.install_dir("/opt/crypto/ipc_tests")
class TestMessagePassingAdapterProcesses:
    """Run the GoogleTest scenario that exercises IPC across target processes."""

    def test_client_and_server_echo_in_separate_processes(
        self, target: Target, target_os: str, install_dir: str, deploy: None
    ):
        num_clients = 4
        service_identifier = f"mp_sep_{uuid.uuid4().hex}"
        logger.info(f"Starting three-client process-separation test for service {service_identifier}")
        process_env = {
            "LD_LIBRARY_PATH": f"{install_dir}/lib:$LD_LIBRARY_PATH",
            "MW_LOG_CONFIG_FILE": f"{install_dir}/etc/logging.json",
            "MESSAGE_PASSING_SERVICE_ID": service_identifier,
        }
        server_process = ProcessRunner(
            target,
            Path(f"{install_dir}/bin/message_passing_adapter_integration_test_process_separation_server"),
            Path(f"/tmp/{service_identifier}_server.log"),
            target_os=target_os,
            env=process_env,
            args=["--gtest_filter=MessagePassingServerProcessTest.StopsAfterTerminationSignal"],
        )
        client_processes = [
            ProcessRunner(
                target,
                Path(f"{install_dir}/bin/message_passing_adapter_integration_test_process_separation_client"),
                Path(f"/tmp/{service_identifier}_client_{client_index}.log"),
                target_os=target_os,
                env={**process_env, "MESSAGE_PASSING_CLIENT_INDEX": str(client_index)},
                args=["--gtest_filter=MessagePassingClientProcessTest.CompletesTwoHundredRequestsAcrossFourThreads"],
            )
            for client_index in range(num_clients)
        ]

        logger.info(f"Starting server GTest for service {service_identifier}")
        assert server_process.start(), server_process.get_log_contents()
        logger.info(f"Server GTest started for service {service_identifier}")

        server_ready = False
        clients_started = False
        client_exit_codes = []
        server_stopped = False
        server_log = ""
        client_logs = []
        try:
            for attempt in range(50):
                server_log = server_process.get_log_contents()
                logger.info(f"Waiting for server readiness ({attempt + 1}/50)")
                if "SERVER_READY" in server_log:
                    server_ready = True
                    logger.info(f"Server is ready for service {service_identifier}")
                    break
                time.sleep(0.1)

            if server_ready:
                logger.info(f"Starting {len(client_processes)} client GTests concurrently")
                clients_started = True
                with ThreadPoolExecutor(max_workers=len(client_processes)) as executor:
                    client_futures = [executor.submit(client_process.run) for client_process in client_processes]
                    client_exit_codes = [client_future.result(timeout=30) for client_future in client_futures]
        finally:
            logger.info(f"Stopping server GTest for service {service_identifier}")
            server_stopped = server_process.terminate(timeout=5)
            server_log = server_process.get_log_contents()
            if clients_started:
                client_logs = [client_process.get_log_contents() for client_process in client_processes]
                for client_index, client_log in enumerate(client_logs):
                    exit_code = client_exit_codes[client_index] if client_index < len(client_exit_codes) else None
                    logger.info(f"Client GTest {client_index} exited with {exit_code}:\n{client_log}")
            logger.info(f"Server GTest stopped gracefully={server_stopped}:\n{server_log}")

        assert server_ready, f"Server GTest did not become ready:\n{server_log}"
        assert len(client_exit_codes) == num_clients
        for client_index, (exit_code, client_log) in enumerate(zip(client_exit_codes, client_logs)):
            assert exit_code == 0, f"Client {client_index} GTest failed with exit code {exit_code}:\n{client_log}"
            assert "[  PASSED  ] 1 test." in client_log, f"Client {client_index} GTest failed:\n{client_log}"

        assert server_stopped, f"Server GTest did not stop after SIGTERM:\n{server_log}"
        assert "[  PASSED  ] 1 test." in server_log, f"Server GTest failed:\n{server_log}"

    def test_server_denies_client_matching_its_uid(
        self, target: Target, target_os: str, install_dir: str, deploy: None
    ):
        service_identifier = f"mp_uid_deny_{uuid.uuid4().hex}"
        logger.info(f"Starting UID-authorization process test for service {service_identifier}")
        process_env = {
            "LD_LIBRARY_PATH": f"{install_dir}/lib:$LD_LIBRARY_PATH",
            "MW_LOG_CONFIG_FILE": f"{install_dir}/etc/logging.json",
            "MESSAGE_PASSING_SERVICE_ID": service_identifier,
        }
        server_process = ProcessRunner(
            target,
            Path(f"{install_dir}/bin/message_passing_adapter_integration_test_process_separation_server"),
            Path(f"/tmp/{service_identifier}_server.log"),
            target_os=target_os,
            env=process_env,
            args=["--gtest_filter=MessagePassingServerProcessTest.DeniesClientMatchingServerUid"],
        )
        client_process = ProcessRunner(
            target,
            Path(f"{install_dir}/bin/message_passing_adapter_integration_test_process_separation_client"),
            Path(f"/tmp/{service_identifier}_client.log"),
            target_os=target_os,
            env=process_env,
            args=["--gtest_filter=MessagePassingClientProcessTest.IsDeniedByServerUidAuthorization"],
        )

        logger.info(f"Starting UID-denying server GTest for service {service_identifier}")
        assert server_process.start(), server_process.get_log_contents()
        logger.info(f"UID-denying server GTest started for service {service_identifier}")

        server_ready = False
        client_started = False
        client_exit_code = None
        server_stopped = False
        server_log = ""
        client_log = ""
        try:
            for attempt in range(50):
                server_log = server_process.get_log_contents()
                logger.info(f"Waiting for UID-denying server readiness ({attempt + 1}/50)")
                if "SERVER_READY" in server_log:
                    server_ready = True
                    logger.info(f"UID-denying server is ready for service {service_identifier}")
                    break
                time.sleep(0.1)

            if server_ready:
                logger.info("Running UID-denied client GTest")
                client_started = True
                client_exit_code = client_process.run()
        finally:
            logger.info(f"Stopping UID-denying server GTest for service {service_identifier}")
            server_stopped = server_process.terminate(timeout=5)
            server_log = server_process.get_log_contents()
            if client_started:
                client_log = client_process.get_log_contents()
                logger.info(f"UID-denied client GTest exited with {client_exit_code}:\n{client_log}")
            logger.info(f"UID-denying server stopped gracefully={server_stopped}:\n{server_log}")

        assert server_ready, f"UID-denying server did not become ready:\n{server_log}"
        assert client_exit_code == 0, (
            f"UID-denied client GTest failed with exit code {client_exit_code}:\n{client_log}"
        )
        assert "[  PASSED  ] 1 test." in client_log, f"UID-denied client GTest failed:\n{client_log}"
        assert server_stopped, f"UID-denying server did not stop after SIGTERM:\n{server_log}"
        assert "[  PASSED  ] 1 test." in server_log, f"UID-denying server GTest failed:\n{server_log}"

    def test_client_unblocks_after_timeout_plus_grace(
        self, target: Target, target_os: str, install_dir: str, deploy: None
    ):
        service_identifier = f"mp_timeout_{uuid.uuid4().hex}"
        logger.info(f"Starting request-timeout process test for service {service_identifier}")
        process_env = {
            "LD_LIBRARY_PATH": f"{install_dir}/lib:$LD_LIBRARY_PATH",
            "MW_LOG_CONFIG_FILE": f"{install_dir}/etc/logging.json",
            "MESSAGE_PASSING_SERVICE_ID": service_identifier,
        }
        server_process = ProcessRunner(
            target,
            Path(f"{install_dir}/bin/message_passing_adapter_integration_test_process_separation_server"),
            Path(f"/tmp/{service_identifier}_server.log"),
            target_os=target_os,
            env=process_env,
            args=["--gtest_filter=MessagePassingServerProcessTest.StopsAfterTerminationSignal"],
        )
        client_process = ProcessRunner(
            target,
            Path(f"{install_dir}/bin/message_passing_adapter_integration_test_process_separation_client"),
            Path(f"/tmp/{service_identifier}_client.log"),
            target_os=target_os,
            env=process_env,
            args=["--gtest_filter=MessagePassingClientProcessTest.ReturnsAfterRequestTimeoutAndGracePeriod"],
        )

        logger.info(f"Starting timeout-test server GTest for service {service_identifier}")
        assert server_process.start(), server_process.get_log_contents()
        logger.info(f"Timeout-test server GTest started for service {service_identifier}")

        server_ready = False
        client_started = False
        client_exit_code = None
        server_stopped = False
        client_log = ""
        server_log = ""
        server_handler_blocked = False
        try:
            for attempt in range(50):
                server_log = server_process.get_log_contents()
                logger.info(f"Waiting for timeout-test server readiness ({attempt + 1}/50)")
                if "SERVER_READY" in server_log:
                    server_ready = True
                    logger.info(f"Timeout-test server is ready for service {service_identifier}")
                    break
                time.sleep(0.1)

            if server_ready:
                logger.info("Running client timeout GTest")
                client_started = True
                client_exit_code = client_process.run()
                for attempt in range(20):
                    server_log = server_process.get_log_contents()
                    logger.info(f"Waiting for blocked-handler marker ({attempt + 1}/20)")
                    if "SERVER_TIMEOUT_HANDLER_BLOCKED" in server_log:
                        server_handler_blocked = True
                        break
                    time.sleep(0.1)
        finally:
            logger.info(f"Stopping timeout-test server GTest for service {service_identifier}")
            server_stopped = server_process.terminate(timeout=5)
            server_log = server_process.get_log_contents()
            if client_started:
                client_log = client_process.get_log_contents()
                logger.info(f"Client timeout GTest exited with {client_exit_code}:\n{client_log}")
            logger.info(f"Timeout-test server stopped gracefully={server_stopped}:\n{server_log}")

        assert server_ready, f"Timeout-test server did not become ready:\n{server_log}"
        assert client_exit_code == 0, (
            f"Timeout-test client GTest failed with exit code {client_exit_code}:\n{client_log}"
        )
        assert "[  PASSED  ] 1 test." in client_log, f"Timeout-test client GTest failed:\n{client_log}"
        assert server_handler_blocked, f"Server did not enter its blocking handler:\n{server_log}"
        assert server_stopped, f"Timeout-test server did not stop after SIGTERM:\n{server_log}"
        assert "[  PASSED  ] 1 test." in server_log, f"Timeout-test server GTest failed:\n{server_log}"

    def test_client_crash_runs_server_disconnect_cleanup(
        self, target: Target, target_os: str, install_dir: str, deploy: None
    ):
        service_identifier = f"mp_crash_cleanup_{uuid.uuid4().hex}"
        logger.info(f"Starting client-crash cleanup test for service {service_identifier}")
        process_env = {
            "LD_LIBRARY_PATH": f"{install_dir}/lib:$LD_LIBRARY_PATH",
            "MW_LOG_CONFIG_FILE": f"{install_dir}/etc/logging.json",
            "MESSAGE_PASSING_SERVICE_ID": service_identifier,
        }
        server_process = ProcessRunner(
            target,
            Path(f"{install_dir}/bin/message_passing_adapter_integration_test_process_separation_server"),
            Path(f"/tmp/{service_identifier}_server.log"),
            target_os=target_os,
            env=process_env,
            args=["--gtest_filter=MessagePassingServerProcessTest.RunsCleanupAfterClientProcessDisconnects"],
        )
        client_process = ProcessRunner(
            target,
            Path(f"{install_dir}/bin/message_passing_adapter_integration_test_process_separation_client"),
            Path(f"/tmp/{service_identifier}_client.log"),
            target_os=target_os,
            env=process_env,
            args=["--gtest_filter=MessagePassingClientProcessTest.CrashesAfterSuccessfulRequest"],
        )

        logger.info(f"Starting cleanup-observing server GTest for service {service_identifier}")
        assert server_process.start(), server_process.get_log_contents()
        logger.info(f"Cleanup-observing server GTest started for service {service_identifier}")

        server_ready = False
        client_started = False
        client_exit_code = None
        client_log = ""
        cleanup_observed = False
        server_stopped = False
        server_log = ""
        try:
            for attempt in range(50):
                server_log = server_process.get_log_contents()
                logger.info(f"Waiting for cleanup-server readiness ({attempt + 1}/50)")
                if "SERVER_READY" in server_log:
                    server_ready = True
                    logger.info(f"Cleanup-observing server is ready for service {service_identifier}")
                    break
                time.sleep(0.1)

            if server_ready:
                logger.info("Running client GTest that will terminate with SIGKILL")
                client_started = True
                client_exit_code = client_process.run()

                for attempt in range(100):
                    server_log = server_process.get_log_contents()
                    logger.info(f"Waiting for disconnect-cleanup marker ({attempt + 1}/100)")
                    if "SERVER_CLEANUP_DONE" in server_log:
                        cleanup_observed = True
                        break
                    time.sleep(0.1)
        finally:
            logger.info(f"Stopping cleanup-observing server GTest for service {service_identifier}")
            server_stopped = server_process.terminate(timeout=5)
            server_log = server_process.get_log_contents()
            if client_started:
                client_log = client_process.get_log_contents()
                logger.info(f"Crash client exited with {client_exit_code}:\n{client_log}")
            logger.info(f"Cleanup-observing server stopped gracefully={server_stopped}:\n{server_log}")

        assert server_ready, f"Cleanup server GTest did not become ready:\n{server_log}"
        assert client_exit_code != 0, f"Client process did not crash:\n{client_log}"
        assert "CLIENT_CRASHING" in client_log, f"Client did not reach its deliberate crash point:\n{client_log}"
        assert cleanup_observed, f"Server disconnect cleanup callback did not run:\n{server_log}"
        assert server_stopped, f"Cleanup server GTest did not stop after SIGTERM:\n{server_log}"
        assert "[  PASSED  ] 1 test." in server_log, f"Cleanup server GTest failed:\n{server_log}"

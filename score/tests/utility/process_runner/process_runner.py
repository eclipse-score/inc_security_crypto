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

"""Remote process management for ITF integration tests."""

import logging
import shlex
import time
from pathlib import Path
from typing import Protocol

logger = logging.getLogger(__name__)

_STARTUP_POLL_INTERVAL_S: float = 0.5


class _Target(Protocol):
    """Minimal interface expected from an ITF target plugin (Docker, QEMU, …)."""

    def execute(self, cmd: str) -> tuple[int, bytes]: ...


class ProcessRunner:
    """Manages a process on a remote ITF target.

    Wraps ITF's ``target.execute()`` / ``target.upload()`` interface to start,
    stop, and query processes on the remote side.  The ITF target object is
    whatever the active ITF plugin (Docker, QEMU, …) injects as the ``target``
    pytest fixture — this class does not import from ITF directly.

    Args:
        target: ITF target object providing ``execute(cmd)`` and ``upload(src, dst)``.
        binary: Absolute path to the executable on the remote target.
        log_file: Remote path where stdout/stderr of the process is redirected.
        target_os: OS name returned by ``uname -s`` on the target.  Use ``"QNX"``
            to enable pidin-based PID lookup; any other value uses ``pgrep``.
        env: Extra environment variables forwarded to the process.
        args: Command-line arguments appended to the binary invocation.
    """

    def __init__(
        self,
        target: _Target,
        binary: Path,
        log_file: Path,
        target_os: str,
        env: dict[str, str] | None = None,
        args: list[str] | None = None,
    ):
        self._target = target
        self._binary = binary
        self._log_file = log_file
        self._target_os = target_os
        self._env = env or {}
        self._args = args or []
        self._pid: str | None = None

    def _find_pid_by_name(self) -> str | None:
        if self._target_os == "QNX":
            # pidin output: "pid tid name ..."; no built-in grep, so pipe externally
            name = self._binary.name
            exit_code, output = self._target.execute(
                f"pidin | grep {name} | grep -v grep"
            )
            lines = output.decode().strip().splitlines()
            if exit_code != 0 or not lines:
                return None
            return lines[0].split()[0]
        exit_code, output = self._target.execute(f"pgrep -f '{self._binary}'")
        lines = output.decode().strip().splitlines()
        if exit_code != 0 or not lines:
            return None
        return lines[0]

    def _clean_log(self) -> bool:
        exit_code, _ = self._target.execute(f"rm -f {self._log_file}")
        return exit_code == 0

    def run(self) -> int:
        """Run the process synchronously and return its exit code.

        Returns:
            The exit code of the process.
        """
        self._clean_log()
        env_str = " ".join(f"{k}={v}" for k, v in self._env.items())
        args_str = shlex.join(self._args)
        cmd = f"env {env_str} {self._binary} {args_str} > {self._log_file} 2>&1"
        exit_code, _ = self._target.execute(cmd)
        return exit_code

    def start(self) -> bool:
        """Start the process in the background.

        Returns:
            True if the process started and its PID was found, False otherwise.
        """
        self._clean_log()
        env_str = " ".join(f"{k}={v}" for k, v in self._env.items())
        args_str = shlex.join(self._args)
        cmd = f"nohup env {env_str} {self._binary} {args_str} > {self._log_file} 2>&1 &"
        exit_code, output = self._target.execute(cmd)
        if exit_code != 0:
            logger.error(f"Failed to start process: {output.decode()}")
            return False

        time.sleep(_STARTUP_POLL_INTERVAL_S)
        self._pid = self._find_pid_by_name()
        if self._pid is None:
            logger.error(
                f"Failed to find process after start. Log:\n{self.get_log_contents()}"
            )
            return False

        logger.info(f"Started '{self._binary}' with PID {self._pid}")
        return True

    def terminate(self, timeout: int = 3) -> bool:
        """Send SIGTERM and wait for the process to exit, falling back to SIGKILL.

        Args:
            timeout: Seconds to wait for graceful shutdown before sending SIGKILL.

        Returns:
            True if the process exited within ``timeout`` seconds, False if SIGKILL was needed.
        """
        assert self._pid is not None, "Process not started"
        exit_code, output = self._target.execute(f"kill -TERM {self._pid}")
        logger.info(f"SIGTERM exit_code={exit_code}, output='{output.decode()}'")

        for i in range(timeout * 10):
            exit_code, _ = self._target.execute(f"kill -0 {self._pid}")
            if exit_code != 0:
                logger.info(f"'{self._binary}' terminated within {i * 0.1:.1f}s")
                return True
            time.sleep(0.1)

        self._target.execute(f"kill -9 {self._pid}")
        logger.info(f"Force-killed '{self._binary}' with SIGKILL after {timeout}s")
        return False

    def get_log_contents(self) -> str:
        """Return the contents of the remote log file.

        Returns:
            Decoded log output, or an empty string if the file could not be read.
        """
        exit_code, output = self._target.execute(f"cat {self._log_file}")
        if exit_code != 0:
            logger.error(f"Failed to read log file: {output.decode()}")
            return ""
        return output.decode()

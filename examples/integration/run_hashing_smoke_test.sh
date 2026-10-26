#!/usr/bin/env bash
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

set -euo pipefail

readonly control_socket="/tmp/crypto_daemon.sock"
readonly endpoint="unix://${control_socket}"
readonly daemon_log="${TEST_UNDECLARED_OUTPUTS_DIR:-${TEST_TMPDIR}}/crypto_daemon.log"

resolve_runfile() {
    local path="$1"
    if [[ "${path}" = /* ]]; then
        printf '%s\n' "${path}"
    elif [[ -e "${path}" ]]; then
        printf '%s\n' "${path}"
    else
        printf '%s\n' "${TEST_SRCDIR}/${path}"
    fi
}

daemon_binary="$(resolve_runfile "$1")"
readonly daemon_binary
client_binary="$(resolve_runfile "$2")"
readonly client_binary
grpc_library="$(resolve_runfile "$3")"
readonly grpc_library
shift 3
runtime_library_path="$(dirname "${grpc_library}")"
for library in "$@"; do
    resolved_library="$(resolve_runfile "${library}")"
    runtime_library_path="${runtime_library_path}:$(dirname "${resolved_library}")"
done
runtime_library_path="${runtime_library_path}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
readonly runtime_library_path
daemon_pid=""

cleanup() {
    if [[ -n "${daemon_pid}" ]] && kill -0 "${daemon_pid}" 2>/dev/null; then
        kill "${daemon_pid}"
        wait "${daemon_pid}" || true
    fi
    rm -f "${control_socket}"
}
trap cleanup EXIT

rm -f "${control_socket}"
LD_LIBRARY_PATH="${runtime_library_path}" "${daemon_binary}" >"${daemon_log}" 2>&1 &
daemon_pid="$!"

for _ in {1..100}; do
    if [[ -S "${control_socket}" ]]; then
        break
    fi
    if ! kill -0 "${daemon_pid}" 2>/dev/null; then
        printf 'Crypto daemon exited before becoming ready.\n' >&2
        cat "${daemon_log}" >&2
        exit 1
    fi
    sleep 0.1
done

if [[ ! -S "${control_socket}" ]]; then
    printf 'Timed out waiting for the crypto daemon socket.\n' >&2
    cat "${daemon_log}" >&2
    exit 1
fi

if ! LD_LIBRARY_PATH="${runtime_library_path}" "${client_binary}" "${endpoint}"; then
    printf 'Hashing client failed. Crypto daemon log:\n' >&2
    cat "${daemon_log}" >&2
    exit 1
fi

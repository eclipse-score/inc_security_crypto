/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

#include <unistd.h>
#include <atomic>
#include <cstdint>

#include <mutex>

#include "score/crypto/daemon/control_plane/control_protocol.h"
#include "score/crypto/ipc/grpc_adapter/src/grpc_id_helpers.h"

namespace score::crypto::ipc
{

std::atomic_uint32_t RequestId::counter = 0;

std::uint64_t RequestId::getRequestId()
{
    static_assert(sizeof(pid_t) == EXPECTED_PID_TYPE_SIZE, "Error: The size of pid_t is not the expected size.");

    uint64_t request_id = getpid();
    request_id <<= EXPECTED_PID_TYPE_SIZE * BITS_PER_BYTE;
    request_id |= counter.fetch_add(1);

    return request_id;
}

decltype(daemon::control_plane::protocol::ControlRequest::uid) InsecureClientId::getUid()
{
    return getuid();
}

decltype(daemon::control_plane::protocol::ControlRequest::pid) InsecureClientId::getPid()
{
    return getpid();
}

}  // namespace score::crypto::ipc

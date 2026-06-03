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

#ifndef GRPC_ID_HELPERS_H
#define GRPC_ID_HELPERS_H

#include <atomic>
#include <cstddef>
#include <cstdint>

#include "score/crypto/daemon/control_plane/control_protocol.h"

namespace score::crypto::ipc
{

constexpr size_t EXPECTED_PID_TYPE_SIZE = sizeof(std::uint32_t);
constexpr size_t EXPECTED_UID_TYPE_SIZE = sizeof(std::uint32_t);
constexpr size_t BITS_PER_BYTE = 8;

class RequestId
{
  public:
    static std::uint64_t getRequestId();

  private:
    static std::atomic_uint32_t counter;
};

class InsecureClientId
{
  public:
    static decltype(daemon::control_plane::protocol::ControlRequest::uid) getUid();
    static decltype(daemon::control_plane::protocol::ControlRequest::pid) getPid();
};

}  // namespace score::crypto::ipc

#endif  // GRPC_ID_HELPERS_H

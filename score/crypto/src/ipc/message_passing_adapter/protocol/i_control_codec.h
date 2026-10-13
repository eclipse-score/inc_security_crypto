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
#ifndef SCORE_CRYPTO_IPC_MESSAGE_PASSING_I_CONTROL_CODEC_H
#define SCORE_CRYPTO_IPC_MESSAGE_PASSING_I_CONTROL_CODEC_H

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/span.hpp"

#include <cstdint>
#include <vector>

namespace score::crypto::ipc::message_passing
{

/**
 * @brief
 * Converts typed control requests and responses to and from transport frame bytes.
 * Implementations provide the wire-format boundary shared by the message-passing client and
 * server. Request metadata can be inspected before full request deserialization.
 * @endrst
 */
class IControlCodec
{
  public:
    struct RequestMetadata final
    {
        daemon::control_plane::protocol::RequestId request_id{0U};
        daemon::control_plane::protocol::ClientId client_id{0U};
        daemon::control_plane::protocol::DataNodeId data_node_id{0U};
        daemon::control_plane::protocol::ExecutionPolicy execution_policy{};
        std::uint32_t timeout_ms{0U};
        daemon::control_plane::protocol::ControlRequestKind kind{
            daemon::control_plane::protocol::ControlRequestKind::kOperation};
    };

    virtual ~IControlCodec() noexcept = default;

    virtual score::crypto::Expected<std::vector<std::uint8_t>, score::crypto::CryptoErrorCode> SerializeRequest(
        const daemon::control_plane::protocol::ControlRequest& request) const noexcept = 0;
    virtual score::crypto::Expected<std::vector<std::uint8_t>, score::crypto::CryptoErrorCode> SerializeResponse(
        const daemon::control_plane::protocol::ControlResponse& response) const noexcept = 0;
    virtual score::crypto::Expected<RequestMetadata, score::crypto::CryptoErrorCode> PeekRequestMetadata(
        score::cpp::span<const std::uint8_t> bytes) const noexcept = 0;
    virtual score::crypto::Expected<std::monostate, score::crypto::CryptoErrorCode> DeserializeRequest(
        score::cpp::span<const std::uint8_t> bytes,
        daemon::control_plane::protocol::ControlRequest& request) const noexcept = 0;
    virtual score::crypto::Expected<std::monostate, score::crypto::CryptoErrorCode> DeserializeResponse(
        score::cpp::span<const std::uint8_t> bytes,
        daemon::control_plane::protocol::ControlResponse& response) const noexcept = 0;

  protected:
    IControlCodec() noexcept = default;
};

}  // namespace score::crypto::ipc::message_passing

#endif  // SCORE_CRYPTO_IPC_MESSAGE_PASSING_I_CONTROL_CODEC_H

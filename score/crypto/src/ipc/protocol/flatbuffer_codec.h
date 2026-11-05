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
#ifndef SCORE_CRYPTO_IPC_PROTOCOL_FLATBUFFER_CODEC_H
#define SCORE_CRYPTO_IPC_PROTOCOL_FLATBUFFER_CODEC_H

#include "score/crypto/src/ipc/protocol/i_control_codec.h"

namespace score::crypto::ipc::protocol
{

/**
 * @brief
 * Implements the control protocol wire format using the FlatBuffers schema.
 * @endrst
 */
class FlatBufferCodec final : public IControlCodec
{
  public:
    score::crypto::Expected<std::vector<std::uint8_t>, score::crypto::CryptoErrorCode> SerializeRequest(
        const daemon::control_plane::protocol::ControlRequest& request) const noexcept override;
    score::crypto::Expected<std::vector<std::uint8_t>, score::crypto::CryptoErrorCode> SerializeResponse(
        const daemon::control_plane::protocol::ControlResponse& response) const noexcept override;
    score::crypto::Expected<RequestMetadata, score::crypto::CryptoErrorCode> PeekRequestMetadata(
        score::cpp::span<const std::uint8_t> bytes) const noexcept override;
    score::crypto::Expected<std::monostate, score::crypto::CryptoErrorCode> DeserializeRequest(
        score::cpp::span<const std::uint8_t> bytes,
        daemon::control_plane::protocol::ControlRequest& request) const noexcept override;
    score::crypto::Expected<std::monostate, score::crypto::CryptoErrorCode> DeserializeResponse(
        score::cpp::span<const std::uint8_t> bytes,
        daemon::control_plane::protocol::ControlResponse& response) const noexcept override;
};

}  // namespace score::crypto::ipc::protocol

#endif  // SCORE_CRYPTO_IPC_PROTOCOL_FLATBUFFER_CODEC_H

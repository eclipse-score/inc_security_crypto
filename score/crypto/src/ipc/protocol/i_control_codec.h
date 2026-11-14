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
#ifndef SCORE_CRYPTO_IPC_PROTOCOL_I_CONTROL_CODEC_H
#define SCORE_CRYPTO_IPC_PROTOCOL_I_CONTROL_CODEC_H

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/span.hpp"

#include <cstdint>
#include <vector>

namespace score::crypto::ipc::protocol
{

/**
 * @brief
 * Converts typed control requests and responses to and from serialized bytes.
 * Implementations provide the wire-format boundary between the crypto control plane and IPC
 * transports. Request metadata can be inspected before full request deserialization.
 * @note SerializeRequest will take a request with an absolute deadline. Internally, the Codec
 * will convert this absolute timeout into a relative one. During DeserializeRequest, the Codec
 * will interpret the relative timeout and convert it back to an absolute deadline.
 * This does allow communication between parties without the need for synchronized clocks.
 * @endrst
 */
class IControlCodec
{
  public:
    /// @brief Metadata available without decoding the full request body.
    struct RequestMetadata final
    {
        /// Request identifier used to correlate the terminal response.
        daemon::control_plane::protocol::RequestId request_id{0U};
        /// Client identifier assigned to the session.
        daemon::control_plane::protocol::ClientId client_id{0U};
        /// Execution policy encoded in the request.
        daemon::control_plane::protocol::ExecutionPolicy execution_policy{};
        /// Data node targeted by the request.
        daemon::control_plane::protocol::DataNodeId data_node_id{0U};
        /// Relative request timeout encoded in milliseconds.
        std::uint32_t timeout_ms{0U};
    };

    virtual ~IControlCodec() noexcept = default;

    /// @brief Serializes a typed control request.
    /// @param request Request to serialize.
    /// @return Serialized bytes, or an error if the request cannot be encoded.
    /// @note The request's absolute deadline will be converted to a relative timeout internally.
    virtual score::crypto::Expected<std::vector<std::uint8_t>, score::crypto::CryptoErrorCode> SerializeRequest(
        const daemon::control_plane::protocol::ControlRequest& request) const noexcept = 0;

    /// @brief Serializes a typed control response.
    /// @param response Response to encode.
    /// @return Serialized bytes, or an error if the response cannot be encoded.
    virtual score::crypto::Expected<std::vector<std::uint8_t>, score::crypto::CryptoErrorCode> SerializeResponse(
        const daemon::control_plane::protocol::ControlResponse& response) const noexcept = 0;

    /// @brief Reads request metadata without fully deserializing the request.
    /// @param bytes Serialized request bytes.
    /// @return Request metadata, or an error if the bytes are invalid.
    virtual score::crypto::Expected<RequestMetadata, score::crypto::CryptoErrorCode> PeekRequestMetadata(
        score::cpp::span<const std::uint8_t> bytes) const noexcept = 0;

    /// @brief Deserializes a control request into owned protocol data.
    /// @param bytes Serialized request bytes.
    /// @param request Receives the decoded request on success.
    /// @return Success, or an error if the bytes are invalid or cannot be decoded.
    /// @note The request's relative deadline will be converted to an absolute timeout internally.
    virtual score::crypto::Expected<std::monostate, score::crypto::CryptoErrorCode> DeserializeRequest(
        score::cpp::span<const std::uint8_t> bytes,
        daemon::control_plane::protocol::ControlRequest& request) const noexcept = 0;

    /// @brief Deserializes a control response into owned protocol data.
    /// @param bytes Serialized response bytes.
    /// @param response Receives the decoded response on success.
    /// @return Success, or an error if the bytes are invalid or cannot be decoded.
    virtual score::crypto::Expected<std::monostate, score::crypto::CryptoErrorCode> DeserializeResponse(
        score::cpp::span<const std::uint8_t> bytes,
        daemon::control_plane::protocol::ControlResponse& response) const noexcept = 0;

  protected:
    IControlCodec() noexcept = default;
};

}  // namespace score::crypto::ipc::protocol

#endif  // SCORE_CRYPTO_IPC_PROTOCOL_I_CONTROL_CODEC_H

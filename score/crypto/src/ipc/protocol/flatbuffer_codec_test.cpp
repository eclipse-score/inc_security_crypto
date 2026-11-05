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

#include "score/crypto/src/ipc/protocol/flatbuffer_codec.h"
#include "score/crypto/src/ipc/protocol/control_generated.h"
#include "score/crypto/src/ipc/protocol/protocol_config.h"

#include <gtest/gtest.h>

#include <flatbuffers/flatbuffers.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <utility>

namespace score::crypto::ipc::protocol::test
{
namespace
{
namespace protocol = daemon::control_plane::protocol;
namespace flatbuffer_protocol = score::crypto::ipc::control;
const FlatBufferCodec flatbuffer_codec{};
const IControlCodec& codec{flatbuffer_codec};

void SetFutureDeadline(protocol::ControlRequest& request)
{
    request.deadline = std::chrono::steady_clock::now() + std::chrono::minutes{5};
}

std::vector<std::uint8_t> BuildRequestWithMissingParameterVector()
{
    flatbuffers::FlatBufferBuilder builder{128U};
    const auto operation = flatbuffer_protocol::CreateSingleOperationRequest(
        builder,
        flatbuffer_protocol::CreateOperationIdentifier(builder, 1U, 1U),
        builder.CreateVector(
            std::vector<flatbuffer_protocol::OperationParameter>{flatbuffer_protocol::OperationParameter::NoParam}),
        {});
    const auto operations = builder.CreateVector({operation});
    const auto policy = flatbuffer_protocol::CreateExecutionPolicy(builder);
    const auto meta_data = flatbuffer_protocol::CreateControlRequestMetaData(
        builder, 1U, 0U, 0U, flatbuffer_protocol::ControlRequestKind::Operation, 0U, policy);
    builder.FinishSizePrefixed(flatbuffer_protocol::CreateControlRequest(builder, meta_data, operations),
                               flatbuffer_protocol::ControlRequestIdentifier());
    return {builder.GetBufferPointer(), builder.GetBufferPointer() + builder.GetSize()};
}

std::vector<std::uint8_t> BuildResponseWithMismatchedParameterVectors()
{
    flatbuffers::FlatBufferBuilder builder{128U};
    const auto operation = flatbuffer_protocol::CreateSingleOperationResponse(
        builder,
        flatbuffer_protocol::CreateOperationIdentifier(builder, 1U, 1U),
        flatbuffer_protocol::CreateOperationResult(builder, 0U),
        builder.CreateVector(
            std::vector<flatbuffer_protocol::OperationParameter>{flatbuffer_protocol::OperationParameter::NoParam}),
        builder.CreateVector(std::vector<flatbuffers::Offset<void>>{}));
    const auto operations = builder.CreateVector({operation});
    builder.FinishSizePrefixed(flatbuffer_protocol::CreateControlResponse(builder, 1U, operations),
                               flatbuffer_protocol::ControlRequestIdentifier());
    return {builder.GetBufferPointer(), builder.GetBufferPointer() + builder.GetSize()};
}

std::vector<std::uint8_t> BuildCancelRequestWithTimeout(const std::uint32_t timeout_ms)
{
    flatbuffers::FlatBufferBuilder builder{128U};
    const auto policy = flatbuffer_protocol::CreateExecutionPolicy(builder);
    const auto meta_data = flatbuffer_protocol::CreateControlRequestMetaData(
        builder, 83U, 0U, 0U, flatbuffer_protocol::ControlRequestKind::Cancel, timeout_ms, policy);
    builder.FinishSizePrefixed(flatbuffer_protocol::CreateControlRequest(builder, meta_data, {}),
                               flatbuffer_protocol::ControlRequestIdentifier());
    return {builder.GetBufferPointer(), builder.GetBufferPointer() + builder.GetSize()};
}

TEST(FlatBufferCodecTest, EnvelopeErrorResponseRoundTrips)
{
    protocol::ControlResponse response{};
    response.request_id = 42U;
    response.operation.operations.push_back(protocol::SingleOperationResponse{
        protocol::kEnvelopeErrorOperationIdentifier,
        static_cast<protocol::OperationResult>(score::crypto::CryptoErrorCode::kProviderBusy),
        {}});

    const auto serialized = codec.SerializeResponse(response);
    ASSERT_TRUE(serialized.has_value());
    const auto bytes = std::move(serialized).value();
    protocol::ControlResponse decoded{};

    ASSERT_TRUE(codec.DeserializeResponse(score::cpp::span<const std::uint8_t>{bytes.data(), bytes.size()}, decoded)
                    .has_value());
    EXPECT_EQ(decoded.request_id, response.request_id);
    EXPECT_TRUE(protocol::IsEnvelopeErrorResponse(decoded));
    ASSERT_EQ(decoded.operation.operations.size(), 1U);
    EXPECT_EQ(decoded.operation.operations.front().result,
              static_cast<protocol::OperationResult>(score::crypto::CryptoErrorCode::kProviderBusy));
}

TEST(FlatBufferCodecTest, EnvelopeOperationIdentifierIsPassedThrough)
{
    protocol::ControlResponse response{};
    response.request_id = 43U;
    response.operation.operations.push_back(protocol::SingleOperationResponse{
        protocol::kEnvelopeErrorOperationIdentifier,
        static_cast<protocol::OperationResult>(score::crypto::CryptoErrorCode::kInternalError),
        {}});
    response.operation.operations.push_back(protocol::SingleOperationResponse{
        protocol::OperationIdentifier{1U, 1U}, protocol::OPERATION_RESULT_SUCCESS, {}});

    const auto serialized = codec.SerializeResponse(response);
    ASSERT_TRUE(serialized.has_value());
    const auto bytes = std::move(serialized).value();
    protocol::ControlResponse decoded{};
    ASSERT_TRUE(codec.DeserializeResponse(score::cpp::span<const std::uint8_t>{bytes.data(), bytes.size()}, decoded)
                    .has_value());
    ASSERT_EQ(decoded.operation.operations.size(), 2U);
    EXPECT_TRUE(protocol::IsEnvelopeErrorOperation(decoded.operation.operations.front().operationId));
}

TEST(FlatBufferCodecTest, RejectsUnknownRequestKind)
{
    protocol::ControlRequest request{};
    SetFutureDeadline(request);
    request.request_id = 19U;
    request.kind = static_cast<protocol::ControlRequestKind>(255U);
    EXPECT_FALSE(codec.SerializeRequest(request).has_value());
}

TEST(FlatBufferCodecTest, AllowsEmptyOperationVector)
{
    protocol::ControlRequest request{};
    SetFutureDeadline(request);
    request.request_id = 24U;
    request.kind = protocol::ControlRequestKind::kOperation;

    const auto serialized = codec.SerializeRequest(request);
    ASSERT_TRUE(serialized.has_value());
    const auto bytes = std::move(serialized).value();
    protocol::ControlRequest decoded{};

    ASSERT_TRUE(codec.DeserializeRequest(score::cpp::span<const std::uint8_t>{bytes.data(), bytes.size()}, decoded)
                    .has_value());
    EXPECT_EQ(decoded.request_id, request.request_id);
    EXPECT_EQ(decoded.kind, protocol::ControlRequestKind::kOperation);
    EXPECT_TRUE(decoded.operation.operations.empty());
}

TEST(FlatBufferCodecTest, ZeroRequestIdPassesThroughCodec)
{
    protocol::ControlRequest request{};
    SetFutureDeadline(request);
    const auto serialized = codec.SerializeRequest(request);
    ASSERT_TRUE(serialized.has_value());
    const auto bytes = std::move(serialized).value();
    protocol::ControlRequest decoded{};
    ASSERT_TRUE(codec.DeserializeRequest(score::cpp::span<const std::uint8_t>{bytes.data(), bytes.size()}, decoded)
                    .has_value());
    EXPECT_EQ(decoded.request_id, 0U);
    EXPECT_TRUE(
        codec.PeekRequestMetadata(score::cpp::span<const std::uint8_t>{bytes.data(), bytes.size()}).has_value());
}

TEST(FlatBufferCodecTest, ZeroResponseIdPassesThroughCodec)
{
    protocol::ControlResponse response{};
    const auto serialized = codec.SerializeResponse(response);
    ASSERT_TRUE(serialized.has_value());
    const auto bytes = std::move(serialized).value();

    protocol::ControlResponse decoded{};
    ASSERT_TRUE(codec.DeserializeResponse(score::cpp::span<const std::uint8_t>{bytes.data(), bytes.size()}, decoded)
                    .has_value());
    EXPECT_EQ(decoded.request_id, 0U);
}

TEST(FlatBufferCodecTest, RejectsOversizedResponseDuringSerialization)
{
    protocol::ControlResponse response{};
    protocol::OwnedBuffer oversized_value(protocol_config::kMaxSerializedBytes + 1U, 0U);
    response.operation.operations.push_back(protocol::SingleOperationResponse{
        protocol::OperationIdentifier{1U, 2U}, protocol::OPERATION_RESULT_SUCCESS, {std::move(oversized_value)}});

    const auto serialized = codec.SerializeResponse(response);
    ASSERT_FALSE(serialized.has_value());
    EXPECT_EQ(serialized.error(), score::crypto::CryptoErrorCode::kInsufficientBufferSize);
}

TEST(FlatBufferCodecTest, EnvelopeOperationIdentifierInRequestPassesThroughCodec)
{
    protocol::ControlRequest request{};
    SetFutureDeadline(request);
    request.request_id = 20U;
    request.operation.operations.push_back(
        protocol::SingleOperationRequest{protocol::kEnvelopeErrorOperationIdentifier, {protocol::NoParam{}}});
    const auto serialized = codec.SerializeRequest(request);
    ASSERT_TRUE(serialized.has_value());
    const auto bytes = std::move(serialized).value();
    protocol::ControlRequest decoded{};
    ASSERT_TRUE(codec.DeserializeRequest(score::cpp::span<const std::uint8_t>{bytes.data(), bytes.size()}, decoded)
                    .has_value());
    ASSERT_EQ(decoded.operation.operations.size(), 1U);
    EXPECT_TRUE(protocol::IsEnvelopeErrorOperation(decoded.operation.operations.front().operationId));
}

TEST(FlatBufferCodecTest, CancellationRequestRoundTrips)
{
    protocol::ControlRequest request{};
    SetFutureDeadline(request);
    request.request_id = 17U;
    request.kind = protocol::ControlRequestKind::kCancel;

    const auto serialized = codec.SerializeRequest(request);
    ASSERT_TRUE(serialized.has_value());
    const auto bytes = std::move(serialized).value();
    protocol::ControlRequest decoded{};

    ASSERT_TRUE(codec.DeserializeRequest(score::cpp::span<const std::uint8_t>{bytes.data(), bytes.size()}, decoded)
                    .has_value());
    EXPECT_EQ(decoded.kind, protocol::ControlRequestKind::kCancel);
    EXPECT_EQ(decoded.request_id, request.request_id);
    EXPECT_TRUE(decoded.operation.operations.empty());
}

TEST(FlatBufferCodecTest, RequestTimeoutBudgetRoundTrips)
{
    protocol::ControlRequest request{};
    request.request_id = 81U;
    request.client_id = 27U;
    request.data_node_id = 39U;
    const auto deadline_start = std::chrono::steady_clock::now();
    request.deadline = deadline_start + std::chrono::minutes{20};

    const auto serialized = codec.SerializeRequest(request);
    ASSERT_TRUE(serialized.has_value());
    const auto bytes = std::move(serialized).value();

    const auto metadata = codec.PeekRequestMetadata(score::cpp::span<const std::uint8_t>{bytes.data(), bytes.size()});
    ASSERT_TRUE(metadata.has_value());
    EXPECT_EQ(metadata->request_id, request.request_id);
    EXPECT_EQ(metadata->client_id, request.client_id);
    EXPECT_EQ(metadata->data_node_id, request.data_node_id);
    EXPECT_GT(metadata->timeout_ms, 10U * 60U * 1000U);
    EXPECT_LE(metadata->timeout_ms, 20U * 60U * 1000U);
    EXPECT_EQ(metadata->kind, protocol::ControlRequestKind::kOperation);

    protocol::ControlRequest decoded{};
    const auto deserialize_started_at = std::chrono::steady_clock::now();
    ASSERT_TRUE(codec.DeserializeRequest(score::cpp::span<const std::uint8_t>{bytes.data(), bytes.size()}, decoded)
                    .has_value());
    EXPECT_EQ(decoded.request_id, request.request_id);
    EXPECT_EQ(decoded.client_id, request.client_id);
    EXPECT_EQ(decoded.data_node_id, request.data_node_id);
    EXPECT_GE(decoded.deadline, deserialize_started_at + std::chrono::milliseconds{metadata->timeout_ms});
}

TEST(FlatBufferCodecTest, ExpiredDeadlineIsRejectedDuringSerialization)
{
    protocol::ControlRequest request{};
    request.request_id = 84U;
    request.deadline = std::chrono::steady_clock::now() - std::chrono::milliseconds{1};

    const auto serialized = codec.SerializeRequest(request);
    ASSERT_FALSE(serialized.has_value());
    EXPECT_EQ(serialized.error(), score::crypto::CryptoErrorCode::kInvalidArgument);
}

TEST(FlatBufferCodecTest, RejectsOversizedRequestDuringSerialization)
{
    protocol::ControlRequest request{};
    SetFutureDeadline(request);
    std::array<char, protocol_config::kMaxSerializedBytes + 1U> oversized_value{};
    request.operation.operations.push_back(protocol::SingleOperationRequest{
        protocol::OperationIdentifier{1U, 2U}, {std::string_view{oversized_value.data(), oversized_value.size()}}});

    const auto serialized = codec.SerializeRequest(request);
    ASSERT_FALSE(serialized.has_value());
    EXPECT_EQ(serialized.error(), score::crypto::CryptoErrorCode::kInsufficientBufferSize);
}

TEST(FlatBufferCodecTest, MetadataDefaultTimeoutIsZero)
{
    flatbuffers::FlatBufferBuilder builder{128U};
    const auto policy = flatbuffer_protocol::CreateExecutionPolicy(builder);
    const std::vector<flatbuffers::Offset<flatbuffer_protocol::SingleOperationRequest>> no_operations{};
    const auto operations = builder.CreateVector(no_operations);
    const auto meta_data = flatbuffer_protocol::CreateControlRequestMetaData(
        builder, 82U, 0U, 0U, flatbuffer_protocol::ControlRequestKind::Operation, 0U, policy);
    builder.FinishSizePrefixed(flatbuffer_protocol::CreateControlRequest(builder, meta_data, operations),
                               flatbuffer_protocol::ControlRequestIdentifier());
    const std::vector<std::uint8_t> bytes{builder.GetBufferPointer(), builder.GetBufferPointer() + builder.GetSize()};

    const auto metadata = codec.PeekRequestMetadata(score::cpp::span<const std::uint8_t>{bytes.data(), bytes.size()});
    ASSERT_TRUE(metadata.has_value());
    EXPECT_EQ(metadata->timeout_ms, 0U);
}

TEST(FlatBufferCodecTest, CancelWithZeroRequestIdPassesThroughCodec)
{
    protocol::ControlRequest request{};
    SetFutureDeadline(request);
    request.request_id = 0U;
    request.kind = protocol::ControlRequestKind::kCancel;
    const auto serialized = codec.SerializeRequest(request);
    ASSERT_TRUE(serialized.has_value());
    const auto bytes = std::move(serialized).value();
    protocol::ControlRequest decoded{};
    ASSERT_TRUE(codec.DeserializeRequest(score::cpp::span<const std::uint8_t>{bytes.data(), bytes.size()}, decoded)
                    .has_value());
    EXPECT_EQ(decoded.request_id, 0U);
}

TEST(FlatBufferCodecTest, CancelWithNonzeroTimeoutIsAcceptedByDecoder)
{
    const auto bytes = BuildCancelRequestWithTimeout(250U);
    protocol::ControlRequest decoded{};
    const auto deserialize_started_at = std::chrono::steady_clock::now();

    EXPECT_TRUE(codec.DeserializeRequest(score::cpp::span<const std::uint8_t>{bytes.data(), bytes.size()}, decoded)
                    .has_value());
    EXPECT_GE(decoded.deadline, deserialize_started_at + std::chrono::milliseconds{250});
    const auto metadata = codec.PeekRequestMetadata(score::cpp::span<const std::uint8_t>{bytes.data(), bytes.size()});
    ASSERT_TRUE(metadata.has_value());
    EXPECT_EQ(metadata->timeout_ms, 250U);
}

TEST(FlatBufferCodecTest, RejectsCancellationWithOperations)
{
    protocol::ControlRequest request{};
    SetFutureDeadline(request);
    request.request_id = 18U;
    request.kind = protocol::ControlRequestKind::kCancel;
    request.operation.operations.push_back(
        protocol::SingleOperationRequest{protocol::OperationIdentifier{1U, 1U}, {protocol::NoParam{}}});
    EXPECT_FALSE(codec.SerializeRequest(request).has_value());
}

TEST(FlatBufferCodecTest, RejectsRequestWithMissingParameterVector)
{
    const auto bytes = BuildRequestWithMissingParameterVector();
    protocol::ControlRequest decoded{};

    EXPECT_FALSE(codec.DeserializeRequest(score::cpp::span<const std::uint8_t>{bytes.data(), bytes.size()}, decoded)
                     .has_value());
}

TEST(FlatBufferCodecTest, RejectsResponseWithMismatchedParameterVectors)
{
    const auto bytes = BuildResponseWithMismatchedParameterVectors();
    protocol::ControlResponse decoded{};

    EXPECT_FALSE(codec.DeserializeResponse(score::cpp::span<const std::uint8_t>{bytes.data(), bytes.size()}, decoded)
                     .has_value());
}

TEST(FlatBufferCodecTest, RequestWithParametersRoundTrips)
{
    protocol::ControlRequest request{};
    SetFutureDeadline(request);
    request.request_id = 7U;
    request.client_id = 0x12345678U;
    request.data_node_id = 9U;
    request.operation.operations.push_back(protocol::SingleOperationRequest{
        protocol::OperationIdentifier{1U, 2U}, {protocol::NoParam{}, std::uint8_t{3U}, std::string_view{"HASH"}}});

    const auto serialized = codec.SerializeRequest(request);
    ASSERT_TRUE(serialized.has_value());
    const auto bytes = std::move(serialized).value();
    protocol::ControlRequest decoded{};

    ASSERT_TRUE(codec.DeserializeRequest(score::cpp::span<const std::uint8_t>{bytes.data(), bytes.size()}, decoded)
                    .has_value());
    ASSERT_EQ(decoded.operation.operations.size(), 1U);
    EXPECT_EQ(decoded.request_id, request.request_id);
    EXPECT_EQ(decoded.client_id, request.client_id);
    EXPECT_EQ(decoded.data_node_id, request.data_node_id);
    EXPECT_EQ(decoded.operation.operations[0].operationId.operationActor, 1U);
    EXPECT_EQ(decoded.operation.operations[0].operationId.operationAction, 2U);
    ASSERT_EQ(decoded.operation.operations[0].parameters.size(), 3U);
    EXPECT_TRUE(std::holds_alternative<protocol::NoParam>(decoded.operation.operations[0].parameters[0]));
    EXPECT_EQ(std::get<std::uint8_t>(decoded.operation.operations[0].parameters[1]), 3U);
    EXPECT_EQ(std::get<std::string_view>(decoded.operation.operations[0].parameters[2]), "HASH");
}

TEST(FlatBufferCodecTest, FinalResponseWithOperationRoundTrips)
{
    protocol::ControlResponse response{};
    response.request_id = 99U;
    response.operation.operations.push_back(protocol::SingleOperationResponse{
        protocol::OperationIdentifier{4U, 5U}, protocol::OPERATION_RESULT_SUCCESS, {}});

    const auto serialized = codec.SerializeResponse(response);
    ASSERT_TRUE(serialized.has_value());
    const auto bytes = std::move(serialized).value();
    protocol::ControlResponse decoded{};

    ASSERT_TRUE(codec.DeserializeResponse(score::cpp::span<const std::uint8_t>{bytes.data(), bytes.size()}, decoded)
                    .has_value());
    ASSERT_EQ(decoded.operation.operations.size(), 1U);
    EXPECT_EQ(decoded.request_id, response.request_id);
    EXPECT_EQ(decoded.operation.operations[0].operationId.operationActor, 4U);
    EXPECT_EQ(decoded.operation.operations[0].operationId.operationAction, 5U);
    EXPECT_EQ(decoded.operation.operations[0].result, protocol::OPERATION_RESULT_SUCCESS);
    EXPECT_TRUE(decoded.operation.operations[0].parameters.empty());
}

TEST(FlatBufferCodecTest, RejectsResponseWithWrongFileIdentifier)
{
    protocol::ControlResponse response{};
    response.request_id = 99U;
    auto serialized = codec.SerializeResponse(response);
    ASSERT_TRUE(serialized.has_value());
    auto bytes = std::move(serialized).value();
    const std::array<std::uint8_t, 4U> identifier{'C', 'C', 'T', 'L'};
    const auto identifier_position = std::search(bytes.begin(), bytes.end(), identifier.begin(), identifier.end());
    ASSERT_NE(identifier_position, bytes.end());
    *identifier_position = static_cast<std::uint8_t>('X');

    protocol::ControlResponse decoded{};
    EXPECT_FALSE(codec.DeserializeResponse(score::cpp::span<const std::uint8_t>{bytes.data(), bytes.size()}, decoded)
                     .has_value());
}

}  // namespace
}  // namespace score::crypto::ipc::protocol::test

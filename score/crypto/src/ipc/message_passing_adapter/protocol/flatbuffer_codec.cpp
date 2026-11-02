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

#include "score/crypto/src/ipc/message_passing_adapter/protocol/flatbuffer_codec.h"

#include "score/crypto/src/ipc/message_passing_adapter/protocol/control_generated.h"

#include <flatbuffers/flatbuffers.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
#include <string_view>
#include <utility>
#include <variant>

namespace score::crypto::ipc::message_passing
{
namespace
{

namespace bl = score::crypto::daemon::control_plane::protocol;
namespace common = score::crypto::daemon::common;
namespace fb = score::crypto::ipc::control;

bool HasValidParameterVectors(const flatbuffers::Vector<fb::OperationParameter>* types,
                              const flatbuffers::Vector<flatbuffers::Offset<void>>* values) noexcept
{
    return (types != nullptr) && (values != nullptr) && (types->size() == values->size());
}

std::pair<std::vector<fb::OperationParameter>, std::vector<flatbuffers::Offset<void>>> BuildRequestParameters(
    const common::RequestParameters& parameters,
    flatbuffers::FlatBufferBuilder& builder)
{
    std::vector<fb::OperationParameter> types;
    std::vector<flatbuffers::Offset<void>> values;

    for (const auto& parameter : parameters)
    {
        if (std::holds_alternative<common::NoParam>(parameter))
        {
            types.push_back(fb::OperationParameter::NoParam);
            values.push_back(fb::CreateNoParam(builder).o);
        }
        else if (std::holds_alternative<bool>(parameter))
        {
            types.push_back(fb::OperationParameter::ValueBool);
            values.push_back(fb::CreateValueBool(builder, std::get<bool>(parameter)).o);
        }
        else if (std::holds_alternative<std::string_view>(parameter))
        {
            types.push_back(fb::OperationParameter::String);
            const auto string_offset = builder.CreateString(std::get<std::string_view>(parameter));
            values.push_back(fb::CreateString(builder, string_offset).o);
        }
        else if (std::holds_alternative<std::uint8_t>(parameter))
        {
            types.push_back(fb::OperationParameter::ValueUint8);
            values.push_back(fb::CreateValueUint8(builder, std::get<std::uint8_t>(parameter)).o);
        }
        else if (std::holds_alternative<std::uint16_t>(parameter))
        {
            types.push_back(fb::OperationParameter::ValueUint16);
            values.push_back(fb::CreateValueUint16(builder, std::get<std::uint16_t>(parameter)).o);
        }
        else if (std::holds_alternative<std::uint32_t>(parameter))
        {
            types.push_back(fb::OperationParameter::ValueUint32);
            values.push_back(fb::CreateValueUint32(builder, std::get<std::uint32_t>(parameter)).o);
        }
        else if (std::holds_alternative<std::uint64_t>(parameter))
        {
            types.push_back(fb::OperationParameter::ValueUint64);
            values.push_back(fb::CreateValueUint64(builder, std::get<std::uint64_t>(parameter)).o);
        }
        else if (std::holds_alternative<common::DataShm>(parameter))
        {
            const auto& shm = std::get<common::DataShm>(parameter);
            types.push_back(fb::OperationParameter::DataShm);
            values.push_back(fb::CreateDataShm(builder,
                                               shm.node_id,
                                               static_cast<std::uint64_t>(shm.offset),
                                               static_cast<std::uint64_t>(shm.size),
                                               static_cast<fb::ShmDirection>(shm.direction))
                                 .o);
        }
        else if (std::holds_alternative<score::cpp::span<const std::uint8_t>>(parameter))
        {
            types.push_back(fb::OperationParameter::DataBufferInBand);
            const auto buffer = std::get<score::cpp::span<const std::uint8_t>>(parameter);
            const auto data_offset = builder.CreateVector(buffer.data(), buffer.size());
            values.push_back(fb::CreateDataBufferInBand(builder, data_offset).o);
        }
        else
        {
            types.push_back(fb::OperationParameter::DataBufferInBand);
            const auto buffer = std::get<score::cpp::span<std::uint8_t>>(parameter);
            const auto data_offset = builder.CreateVector(buffer.data(), buffer.size());
            values.push_back(fb::CreateDataBufferInBand(builder, data_offset).o);
        }
    }

    return {std::move(types), std::move(values)};
}

std::pair<std::vector<fb::OperationParameter>, std::vector<flatbuffers::Offset<void>>> BuildResponseParameters(
    const common::ResponseParameters& parameters,
    flatbuffers::FlatBufferBuilder& builder)
{
    std::vector<fb::OperationParameter> types;
    std::vector<flatbuffers::Offset<void>> values;

    for (const auto& parameter : parameters)
    {
        if (std::holds_alternative<common::NoParam>(parameter))
        {
            types.push_back(fb::OperationParameter::NoParam);
            values.push_back(fb::CreateNoParam(builder).o);
        }
        else if (std::holds_alternative<bool>(parameter))
        {
            types.push_back(fb::OperationParameter::ValueBool);
            values.push_back(fb::CreateValueBool(builder, std::get<bool>(parameter)).o);
        }
        else if (std::holds_alternative<std::uint8_t>(parameter))
        {
            types.push_back(fb::OperationParameter::ValueUint8);
            values.push_back(fb::CreateValueUint8(builder, std::get<std::uint8_t>(parameter)).o);
        }
        else if (std::holds_alternative<std::uint16_t>(parameter))
        {
            types.push_back(fb::OperationParameter::ValueUint16);
            values.push_back(fb::CreateValueUint16(builder, std::get<std::uint16_t>(parameter)).o);
        }
        else if (std::holds_alternative<std::uint32_t>(parameter))
        {
            types.push_back(fb::OperationParameter::ValueUint32);
            values.push_back(fb::CreateValueUint32(builder, std::get<std::uint32_t>(parameter)).o);
        }
        else if (std::holds_alternative<std::uint64_t>(parameter))
        {
            types.push_back(fb::OperationParameter::ValueUint64);
            values.push_back(fb::CreateValueUint64(builder, std::get<std::uint64_t>(parameter)).o);
        }
        else if (std::holds_alternative<common::OwnedString>(parameter))
        {
            types.push_back(fb::OperationParameter::String);
            const auto& string_value = std::get<common::OwnedString>(parameter);
            const auto string_offset = builder.CreateString(string_value);
            values.push_back(fb::CreateString(builder, string_offset).o);
        }
        else if (std::holds_alternative<common::OwnedBuffer>(parameter))
        {
            types.push_back(fb::OperationParameter::DataBufferInBand);
            const auto& buffer = std::get<common::OwnedBuffer>(parameter);
            const auto data_offset = builder.CreateVector(buffer.data(), buffer.size());
            values.push_back(fb::CreateDataBufferInBand(builder, data_offset).o);
        }
        else
        {
            types.push_back(fb::OperationParameter::DataBufferInBand);
            const auto buffer = std::get<score::cpp::span<const std::uint8_t>>(parameter);
            const auto data_offset = builder.CreateVector(buffer.data(), buffer.size());
            values.push_back(fb::CreateDataBufferInBand(builder, data_offset).o);
        }
    }

    return {std::move(types), std::move(values)};
}

common::RequestParameters ExtractRequestParameters(const flatbuffers::Vector<fb::OperationParameter>* types,
                                                   const flatbuffers::Vector<flatbuffers::Offset<void>>* values)
{
    common::RequestParameters parameters;
    if ((types == nullptr) || (values == nullptr) || (types->size() != values->size()))
    {
        return parameters;
    }

    for (flatbuffers::uoffset_t index = 0U; index < types->size(); ++index)
    {
        const auto type = static_cast<fb::OperationParameter>(types->Get(index));
        const auto* value = values->Get(index);
        if (value == nullptr)
        {
            return {};
        }

        switch (type)
        {
            case fb::OperationParameter::NoParam:
                parameters.emplace_back(common::NoParam{});
                break;
            case fb::OperationParameter::ValueBool:
                parameters.emplace_back(static_cast<const fb::ValueBool*>(static_cast<const void*>(value))->val());
                break;
            case fb::OperationParameter::ValueUint8:
                parameters.emplace_back(static_cast<const fb::ValueUint8*>(static_cast<const void*>(value))->val());
                break;
            case fb::OperationParameter::ValueUint16:
                parameters.emplace_back(static_cast<const fb::ValueUint16*>(static_cast<const void*>(value))->val());
                break;
            case fb::OperationParameter::ValueUint32:
                parameters.emplace_back(static_cast<const fb::ValueUint32*>(static_cast<const void*>(value))->val());
                break;
            case fb::OperationParameter::ValueUint64:
                parameters.emplace_back(static_cast<const fb::ValueUint64*>(static_cast<const void*>(value))->val());
                break;
            case fb::OperationParameter::String:
            {
                const auto* string_value = static_cast<const fb::String*>(static_cast<const void*>(value))->val();
                if (string_value == nullptr)
                {
                    return {};
                }
                parameters.emplace_back(std::string_view{string_value->data(), string_value->size()});
                break;
            }
            case fb::OperationParameter::DataBufferInBand:
            {
                const auto* buffer = static_cast<const fb::DataBufferInBand*>(static_cast<const void*>(value))->val();
                if (buffer == nullptr)
                {
                    return {};
                }
                parameters.emplace_back(score::cpp::span<const std::uint8_t>{buffer->Data(), buffer->size()});
                break;
            }
            case fb::OperationParameter::DataShm:
            {
                const auto* shm = static_cast<const fb::DataShm*>(static_cast<const void*>(value));
                if (shm == nullptr)
                {
                    return {};
                }
                parameters.emplace_back(common::DataShm{shm->node_id(),
                                                        static_cast<std::size_t>(shm->offset()),
                                                        static_cast<std::size_t>(shm->size()),
                                                        static_cast<common::ShmDirection>(shm->direction())});
                break;
            }
            case fb::OperationParameter::DataBufferDataPlane:
            case fb::OperationParameter::NONE:
            default:
                return {};
        }
    }
    return parameters;
}

common::ResponseParameters ExtractResponseParameters(const flatbuffers::Vector<fb::OperationParameter>* types,
                                                     const flatbuffers::Vector<flatbuffers::Offset<void>>* values)
{
    common::ResponseParameters parameters;
    if ((types == nullptr) || (values == nullptr) || (types->size() != values->size()))
    {
        return parameters;
    }

    for (flatbuffers::uoffset_t index = 0U; index < types->size(); ++index)
    {
        const auto type = static_cast<fb::OperationParameter>(types->Get(index));
        const auto* value = values->Get(index);
        if (value == nullptr)
        {
            return {};
        }
        switch (type)
        {
            case fb::OperationParameter::NoParam:
                parameters.emplace_back(common::NoParam{});
                break;
            case fb::OperationParameter::ValueBool:
                parameters.emplace_back(static_cast<const fb::ValueBool*>(static_cast<const void*>(value))->val());
                break;
            case fb::OperationParameter::ValueUint8:
                parameters.emplace_back(static_cast<const fb::ValueUint8*>(static_cast<const void*>(value))->val());
                break;
            case fb::OperationParameter::ValueUint16:
                parameters.emplace_back(static_cast<const fb::ValueUint16*>(static_cast<const void*>(value))->val());
                break;
            case fb::OperationParameter::ValueUint32:
                parameters.emplace_back(static_cast<const fb::ValueUint32*>(static_cast<const void*>(value))->val());
                break;
            case fb::OperationParameter::ValueUint64:
                parameters.emplace_back(static_cast<const fb::ValueUint64*>(static_cast<const void*>(value))->val());
                break;
            case fb::OperationParameter::String:
            {
                const auto* string_value = static_cast<const fb::String*>(static_cast<const void*>(value))->val();
                if (string_value == nullptr)
                {
                    return {};
                }
                parameters.emplace_back(common::OwnedString{string_value->data(), string_value->size()});
                break;
            }
            case fb::OperationParameter::DataBufferInBand:
            {
                const auto* buffer = static_cast<const fb::DataBufferInBand*>(static_cast<const void*>(value))->val();
                if (buffer == nullptr)
                {
                    return {};
                }
                parameters.emplace_back(common::OwnedBuffer{buffer->begin(), buffer->end()});
                break;
            }
            case fb::OperationParameter::DataBufferDataPlane:
            case fb::OperationParameter::DataShm:
            case fb::OperationParameter::NONE:
            default:
                return {};
        }
    }
    return parameters;
}

}  // namespace

score::crypto::Expected<std::vector<std::uint8_t>, score::crypto::CryptoErrorCode> FlatBufferCodec::SerializeRequest(
    const bl::ControlRequest& request) const noexcept
{
    // FlatBuffers and protocol vectors allocate while encoding; convert failures to the codec error.
    try
    {
        std::uint32_t timeout_ms{0U};
        const auto now = std::chrono::steady_clock::now();
        if (request.deadline > now)
        {
            const auto remaining_ms = std::chrono::ceil<std::chrono::milliseconds>(request.deadline - now);
            timeout_ms = static_cast<std::uint32_t>(remaining_ms.count());
        }
        else
        {
            // The request deadline has already passed, so we cannot proceed.
            return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInvalidArgument);
        }
        flatbuffers::FlatBufferBuilder builder;
        flatbuffers::Offset<fb::OperationRequestBatch> operation_batch{};
        if (((request.kind != bl::ControlRequestKind::kOperation) &&
             (request.kind != bl::ControlRequestKind::kCancel)) ||
            ((request.kind == bl::ControlRequestKind::kCancel) && !request.operation.operations.empty()))
        {
            return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInvalidFormat);
        }
        if (request.kind == bl::ControlRequestKind::kOperation)
        {
            std::vector<flatbuffers::Offset<fb::SingleOperationRequest>> operations;
            for (const auto& operation : request.operation.operations)
            {
                const auto operation_id = fb::CreateOperationIdentifier(
                    builder, operation.operationId.operationActor, operation.operationId.operationAction);
                auto parameters = BuildRequestParameters(operation.parameters, builder);
                const auto parameter_types = builder.CreateVector(parameters.first);
                const auto parameter_values = builder.CreateVector(parameters.second);
                operations.push_back(
                    fb::CreateSingleOperationRequest(builder, operation_id, parameter_types, parameter_values));
            }
            operation_batch = fb::CreateOperationRequestBatch(builder, builder.CreateVector(operations));
        }
        const auto execution_policy = fb::CreateExecutionPolicy(builder);
        const auto meta_data = fb::CreateControlRequestMetaData(builder,
                                                                request.request_id,
                                                                request.client_id,
                                                                request.data_node_id,
                                                                static_cast<fb::ControlRequestKind>(request.kind),
                                                                timeout_ms,
                                                                execution_policy);
        const auto root = fb::CreateControlRequest(builder, meta_data, operation_batch);
        builder.FinishSizePrefixed(root, fb::ControlRequestIdentifier());
        return std::vector<std::uint8_t>{builder.GetBufferPointer(), builder.GetBufferPointer() + builder.GetSize()};
    }
    catch (const std::bad_alloc&)
    {
        return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kAllocationFailed);
    }
    catch (...)
    {
        return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInternalError);
    }
}

score::crypto::Expected<std::vector<std::uint8_t>, score::crypto::CryptoErrorCode> FlatBufferCodec::SerializeResponse(
    const bl::ControlResponse& response) const noexcept
{
    // FlatBuffers and protocol vectors allocate while encoding; convert failures to the codec error.
    try
    {
        flatbuffers::FlatBufferBuilder builder;
        std::vector<flatbuffers::Offset<fb::SingleOperationResponse>> operations;
        for (const auto& operation : response.operation.operations)
        {
            const auto operation_id = fb::CreateOperationIdentifier(
                builder, operation.operationId.operationActor, operation.operationId.operationAction);
            const auto result = fb::CreateOperationResult(builder, static_cast<std::uint32_t>(operation.result));
            auto parameters = BuildResponseParameters(operation.parameters, builder);
            const auto parameter_types = builder.CreateVector(parameters.first);
            const auto parameter_values = builder.CreateVector(parameters.second);
            operations.push_back(
                fb::CreateSingleOperationResponse(builder, operation_id, result, parameter_types, parameter_values));
        }
        const auto operation_batch = fb::CreateOperationResponseBatch(builder, builder.CreateVector(operations));
        const auto root = fb::CreateControlResponse(builder, response.request_id, operation_batch);
        builder.FinishSizePrefixed(root, fb::ControlRequestIdentifier());
        return std::vector<std::uint8_t>{builder.GetBufferPointer(), builder.GetBufferPointer() + builder.GetSize()};
    }
    catch (const std::bad_alloc&)
    {
        return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kAllocationFailed);
    }
    catch (...)
    {
        return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInternalError);
    }
}

score::crypto::Expected<FlatBufferCodec::RequestMetadata, score::crypto::CryptoErrorCode>
FlatBufferCodec::PeekRequestMetadata(const score::cpp::span<const std::uint8_t> bytes) const noexcept
{
    flatbuffers::Verifier verifier{bytes.data(), bytes.size()};
    if (!fb::VerifySizePrefixedControlRequestBuffer(verifier))
    {
        return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInvalidFormat);
    }
    const auto* root = flatbuffers::GetSizePrefixedRoot<fb::ControlRequest>(bytes.data());
    if ((root == nullptr) || (root->meta_data() == nullptr) || (root->meta_data()->execution_policy() == nullptr))
    {
        return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInvalidFormat);
    }
    const auto* meta_data = root->meta_data();
    const auto kind = meta_data->request_type();
    if (kind > fb::ControlRequestKind::Cancel)
    {
        return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInvalidFormat);
    }
    if ((kind == fb::ControlRequestKind::Operation) && (root->operation_batch() == nullptr))
    {
        return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInvalidFormat);
    }
    if ((kind == fb::ControlRequestKind::Cancel) && (root->operation_batch() != nullptr))
    {
        return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInvalidFormat);
    }
    return RequestMetadata{meta_data->request_id(),
                           meta_data->client_id(),
                           meta_data->data_node_id(),
                           {},
                           meta_data->timeout_ms(),
                           static_cast<bl::ControlRequestKind>(kind)};
}

score::crypto::Expected<std::monostate, score::crypto::CryptoErrorCode> FlatBufferCodec::DeserializeRequest(
    score::cpp::span<const std::uint8_t> bytes,
    bl::ControlRequest& request) const noexcept
{
    // Decoding owns strings and buffers; clear partially decoded output if allocation fails.
    try
    {
        request = bl::ControlRequest{};
        flatbuffers::Verifier verifier{bytes.data(), bytes.size()};
        if (!fb::VerifySizePrefixedControlRequestBuffer(verifier))
        {
            return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInvalidFormat);
        }
        const auto* root = flatbuffers::GetSizePrefixedRoot<fb::ControlRequest>(bytes.data());
        if ((root == nullptr) || (root->meta_data() == nullptr) || (root->meta_data()->execution_policy() == nullptr))
        {
            return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInvalidFormat);
        }
        const auto* meta_data = root->meta_data();
        const auto kind = meta_data->request_type();
        if (kind > fb::ControlRequestKind::Cancel)
        {
            return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInvalidFormat);
        }
        if (((kind == fb::ControlRequestKind::Operation) && (root->operation_batch() == nullptr)) ||
            ((kind == fb::ControlRequestKind::Cancel) && (root->operation_batch() != nullptr)))
        {
            return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInvalidFormat);
        }
        request.kind = static_cast<bl::ControlRequestKind>(kind);
        request.request_id = meta_data->request_id();
        request.client_id = meta_data->client_id();
        request.data_node_id = meta_data->data_node_id();
        // TODO: Will be replaced with proper execution policy handling in the future.
        request.execution_policy = {};
        request.deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(meta_data->timeout_ms());
        if (kind == fb::ControlRequestKind::Cancel)
        {
            return {};
        }
        const auto* operations = root->operation_batch()->operations();
        if (operations == nullptr)
        {
            return {};
        }
        for (const auto* operation : *operations)
        {
            if ((operation == nullptr) || (operation->operation_id() == nullptr))
            {
                return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInvalidFormat);
            }
            bl::SingleOperationRequest decoded{};
            decoded.operationId.operationActor = operation->operation_id()->operation_actor();
            decoded.operationId.operationAction = operation->operation_id()->operation_action();
            if (!HasValidParameterVectors(operation->parameter_type(), operation->parameter()))
            {
                return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInvalidFormat);
            }
            decoded.parameters = ExtractRequestParameters(operation->parameter_type(), operation->parameter());
            if (decoded.parameters.size() != operation->parameter_type()->size())
            {
                return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInvalidFormat);
            }
            request.operation.operations.push_back(std::move(decoded));
        }
        return {};
    }
    catch (const std::bad_alloc&)
    {
        request = bl::ControlRequest{};
        return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kAllocationFailed);
    }
    catch (...)
    {
        request = bl::ControlRequest{};
        return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInternalError);
    }
}

score::crypto::Expected<std::monostate, score::crypto::CryptoErrorCode> FlatBufferCodec::DeserializeResponse(
    score::cpp::span<const std::uint8_t> bytes,
    bl::ControlResponse& response) const noexcept
{
    // Response decoding owns strings and buffers; clear partial output if allocation fails.
    try
    {
        response = bl::ControlResponse{};
        flatbuffers::Verifier verifier{bytes.data(), bytes.size()};
        if (!verifier.VerifySizePrefixedBuffer<fb::ControlResponse>(fb::ControlRequestIdentifier()))
        {
            return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInvalidFormat);
        }
        const auto* root = flatbuffers::GetSizePrefixedRoot<fb::ControlResponse>(bytes.data());
        if ((root == nullptr) || (root->operation_batch() == nullptr))
        {
            return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInvalidFormat);
        }
        response.request_id = root->request_id();
        const auto* operations = root->operation_batch()->operations();
        if (operations == nullptr)
        {
            return {};
        }
        for (const auto* operation : *operations)
        {
            if ((operation == nullptr) || (operation->operation_id() == nullptr) || (operation->result() == nullptr))
            {
                return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInvalidFormat);
            }
            bl::SingleOperationResponse decoded{};
            decoded.operationId.operationActor = operation->operation_id()->operation_actor();
            decoded.operationId.operationAction = operation->operation_id()->operation_action();
            decoded.result = static_cast<bl::OperationResult>(operation->result()->val());
            if (!HasValidParameterVectors(operation->parameter_type(), operation->parameter()))
            {
                return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInvalidFormat);
            }
            decoded.parameters = ExtractResponseParameters(operation->parameter_type(), operation->parameter());
            if (decoded.parameters.size() != operation->parameter_type()->size())
            {
                return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInvalidFormat);
            }
            response.operation.operations.push_back(std::move(decoded));
        }
        return {};
    }
    catch (const std::bad_alloc&)
    {
        response = bl::ControlResponse{};
        return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kAllocationFailed);
    }
    catch (...)
    {
        response = bl::ControlResponse{};
        return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInternalError);
    }
}

}  // namespace score::crypto::ipc::message_passing

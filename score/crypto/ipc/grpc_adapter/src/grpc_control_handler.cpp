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

#include "score/crypto/ipc/grpc_adapter/grpc_control_handler.h"
#include "score/crypto/daemon/common/types.hpp"
#include "score/crypto/daemon/control_plane/control_protocol.h"
#include "score/crypto/daemon/control_plane/i_handler_chain_factory.hpp"
#include "score/crypto/daemon/control_plane/i_request_handler.hpp"
#include "score/crypto/ipc/grpc_adapter/control.grpc.fb.h"
#include "score/crypto/ipc/grpc_adapter/control_generated.h"

#include "flatbuffers/grpc.h"
#include <grpcpp/grpcpp.h>

#include "score/mw/log/logging.h"
#include <cstddef>
#include <cstdint>

#include <memory>
#include <sstream>
#include <string_view>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

namespace score::crypto::ipc
{

// Thread-local handler storage (one per gRPC worker thread)
thread_local std::unique_ptr<score::crypto::daemon::control_plane::IRequestHandler>
    GrpcControlServiceAdapter::_thread_handler = nullptr;

GrpcControlServiceAdapter::GrpcControlServiceAdapter(
    std::unique_ptr<score::crypto::daemon::control_plane::IHandlerChainFactory> factory)
    : _factory(std::move(factory))
{
}

grpc::Status GrpcControlServiceAdapter::Execute(
    grpc::ServerContext* /*context*/,
    const flatbuffers::grpc::Message<score::crypto::ipc::control::ControlRequest>* request,
    flatbuffers::grpc::Message<score::crypto::ipc::control::ControlResponse>* response)
{

    const auto* fb_req = request->GetRoot();
    if (!fb_req)
    {
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid request");
    }

    // Convert FlatBuffer → Business Logic
    auto bl_req = ConvertRequest(fb_req);

    std::ostringstream tid;
    tid << std::this_thread::get_id();

    score::mw::log::LogDebug() << "[GrpcControlServiceAdapter] [Server Thread" << tid.str() << "] "
                               << "Processing request with RequestID:" << bl_req.request_id
                               << " | User Id:" << bl_req.client_id << " | DataNodeId:" << bl_req.data_node_id;

    // Lazy initialization: create handler for this thread on first request
    if (!_thread_handler)
    {
        score::mw::log::LogDebug() << "[GrpcControlServiceAdapter] [Server Thread" << tid.str() << "] "
                                   << "Initializing thread-local request handler";
        _thread_handler = _factory->CreateRequestHandler();
    }

    // Execute business logic (transport-agnostic)
    auto bl_resp = _thread_handler->processRequest(bl_req);

    score::mw::log::LogDebug() << "[GrpcControlServiceAdapter] [Server Thread" << tid.str() << "] "
                               << "Processed request, returning response with RequestID:" << bl_resp.request_id
                               << " (Request had:" << bl_req.request_id << ")";

    // Convert Business Logic → FlatBuffer
    ConvertResponse(bl_resp, response);

    return grpc::Status::OK;
}

daemon::control_plane::protocol::ControlRequest GrpcControlServiceAdapter::ConvertRequest(
    const score::crypto::ipc::control::ControlRequest* fb_req)
{
    // Create a new ControlRequest with extracted data from FlatBuffer
    daemon::control_plane::protocol::ControlRequest bl_req{};

    // Extract scalar fields from FlatBuffer
    bl_req.request_id = fb_req->request_id();

    // Extract client_id (union field) - assign as the union variant
    bl_req.client_id = fb_req->client_id();

    // Extract data_node_id (union field) - assign as the union variant
    bl_req.data_node_id = fb_req->data_node_id();

    // Extract operation batch
    const auto* fb_op_batch = fb_req->operation_batch();
    if (fb_op_batch && fb_op_batch->operations())
    {
        // Iterate over each SingleOperationRequest in the batch
        for (const auto* fb_single_op : *fb_op_batch->operations())
        {
            if (!fb_single_op)
                continue;

            // Create a SingleOperationRequest in business logic
            daemon::control_plane::protocol::SingleOperationRequest bl_single_op{};

            // Extract operation identifier
            const auto* fb_op_id = fb_single_op->operation_id();
            if (fb_op_id)
            {
                bl_single_op.operationId.operationActor = fb_op_id->operation_actor();
                bl_single_op.operationId.operationAction = fb_op_id->operation_action();
            }

            // Extract request parameters
            bl_single_op.parameters =
                ExtractRequestParameters(fb_single_op->parameter_type(), fb_single_op->parameter());

            // Add the single operation to the batch
            bl_req.operation.operations.push_back(bl_single_op);
        }
    }

    return bl_req;
}

void GrpcControlServiceAdapter::ConvertResponse(
    const daemon::control_plane::protocol::ControlResponse& bl_resp,
    flatbuffers::grpc::Message<score::crypto::ipc::control::ControlResponse>* fb_resp)
{
    // Create a FlatBuffer builder for constructing the response
    flatbuffers::grpc::MessageBuilder builder;

    // Build operation response batch
    std::vector<::flatbuffers::Offset<score::crypto::ipc::control::SingleOperationResponse>> fb_single_responses;

    for (const auto& bl_single_resp : bl_resp.operation.operations)
    {
        // Build operation identifier
        auto fb_op_id = score::crypto::ipc::control::CreateOperationIdentifier(
            builder, bl_single_resp.operationId.operationActor, bl_single_resp.operationId.operationAction);

        // Build operation result
        auto fb_result =
            score::crypto::ipc::control::CreateOperationResult(builder, static_cast<uint32_t>(bl_single_resp.result));

        // Build response parameters
        auto [fb_param_types, fb_params] = BuildResponseParameters(bl_single_resp.parameters, builder);

        // Create parameter vectors
        auto fb_param_types_vec = builder.CreateVector(fb_param_types);
        auto fb_params_vec = builder.CreateVector(fb_params);

        // Build single operation response
        auto fb_single_resp = score::crypto::ipc::control::CreateSingleOperationResponse(
            builder, fb_op_id, fb_result, fb_param_types_vec, fb_params_vec);

        fb_single_responses.push_back(fb_single_resp);
    }

    // Create operation response batch
    auto fb_op_batch =
        score::crypto::ipc::control::CreateOperationResponseBatch(builder, builder.CreateVector(fb_single_responses));

    // Build ControlResponse
    auto fb_response = score::crypto::ipc::control::CreateControlResponse(builder, bl_resp.request_id, fb_op_batch);

    // Finish the builder and extract the Message
    builder.Finish(fb_response);
    *fb_resp = builder.GetMessage<score::crypto::ipc::control::ControlResponse>();
}

std::pair<std::vector<uint8_t>, std::vector<::flatbuffers::Offset<void>>>
GrpcControlServiceAdapter::BuildResponseParameters(const daemon::common::ResponseParameters& bl_params,
                                                   flatbuffers::grpc::MessageBuilder& builder)
{
    std::vector<uint8_t> fb_param_types;
    std::vector<::flatbuffers::Offset<void>> fb_params;

    for (const auto& bl_param : bl_params)
    {
        if (std::holds_alternative<daemon::control_plane::protocol::NoParam>(bl_param))
        {
            fb_param_types.emplace_back(score::crypto::ipc::control::OperationParameter_NoParam);
            auto fb_no_param = score::crypto::ipc::control::CreateNoParam(builder);
            fb_params.emplace_back(fb_no_param.o);
        }
        else if (std::holds_alternative<bool>(bl_param))
        {
            const auto& val = std::get<bool>(bl_param);
            fb_param_types.emplace_back(score::crypto::ipc::control::OperationParameter_ValueBool);
            auto fb_val = score::crypto::ipc::control::CreateValueBool(builder, val);
            fb_params.emplace_back(fb_val.o);
        }
        else if (std::holds_alternative<std::uint8_t>(bl_param))
        {
            const auto& val = std::get<std::uint8_t>(bl_param);
            fb_param_types.emplace_back(score::crypto::ipc::control::OperationParameter_ValueUint8);
            auto fb_val = score::crypto::ipc::control::CreateValueUint8(builder, val);
            fb_params.emplace_back(fb_val.o);
        }
        else if (std::holds_alternative<std::uint16_t>(bl_param))
        {
            const auto& val = std::get<std::uint16_t>(bl_param);
            fb_param_types.emplace_back(score::crypto::ipc::control::OperationParameter_ValueUint16);
            auto fb_val = score::crypto::ipc::control::CreateValueUint16(builder, val);
            fb_params.emplace_back(fb_val.o);
        }
        else if (std::holds_alternative<std::uint32_t>(bl_param))
        {
            const auto& val = std::get<std::uint32_t>(bl_param);
            fb_param_types.emplace_back(score::crypto::ipc::control::OperationParameter_ValueUint32);
            auto fb_val = score::crypto::ipc::control::CreateValueUint32(builder, val);
            fb_params.emplace_back(fb_val.o);
        }
        else if (std::holds_alternative<std::uint64_t>(bl_param))
        {
            const auto& val = std::get<std::uint64_t>(bl_param);
            fb_param_types.emplace_back(score::crypto::ipc::control::OperationParameter_ValueUint64);
            auto fb_val = score::crypto::ipc::control::CreateValueUint64(builder, val);
            fb_params.emplace_back(fb_val.o);
        }
        else if (std::holds_alternative<daemon::control_plane::protocol::OwnedString>(bl_param))
        {
            const auto& str = std::get<daemon::control_plane::protocol::OwnedString>(bl_param);
            fb_param_types.emplace_back(score::crypto::ipc::control::OperationParameter_String);
            auto fb_str_offset = builder.CreateString(str.data(), str.size());
            auto fb_string = score::crypto::ipc::control::CreateString(builder, fb_str_offset);
            fb_params.emplace_back(fb_string.o);
        }
        else if (std::holds_alternative<daemon::control_plane::protocol::OwnedBuffer>(bl_param))
        {
            const auto& buffer = std::get<daemon::control_plane::protocol::OwnedBuffer>(bl_param);
            fb_param_types.emplace_back(score::crypto::ipc::control::OperationParameter_DataBufferInBand);
            // Create FlatBuffer vector directly from buffer data without intermediate copy
            auto fb_data = builder.CreateVector(buffer.data(), buffer.size());
            auto fb_buffer = score::crypto::ipc::control::CreateDataBufferInBand(builder, fb_data);
            fb_params.emplace_back(fb_buffer.o);
        }
        // Convert non-owning buffers to owning ones for the transfer via the IPC
        else if (std::holds_alternative<score::crypto::daemon::common::VirtualMemoryBufferConst>(bl_param))
        {
            const auto& buffer = std::get<score::crypto::daemon::common::VirtualMemoryBufferConst>(bl_param);
            fb_param_types.emplace_back(score::crypto::ipc::control::OperationParameter_DataBufferInBand);
            // Create FlatBuffer vector directly from buffer data without intermediate copy
            auto fb_data = builder.CreateVector(buffer.data, buffer.size);
            auto fb_buffer = score::crypto::ipc::control::CreateDataBufferInBand(builder, fb_data);
            fb_params.emplace_back(fb_buffer.o);
        }
        else
        {
            // TODO: Not all types of the varaint are implemented. However all
            // which are currently used are implemented.
            // In case we end up here, we may need to implemented serialization / deserializazion
            // for the concrete type.

            score::mw::log::LogError() << "[GrpcControlServiceAdapter] ERROR - Unsupported parameter type in response";
            // Skip unsupported parameter types
            continue;
        }
    }

    return {fb_param_types, fb_params};
}

daemon::common::RequestParameters GrpcControlServiceAdapter::ExtractRequestParameters(
    const flatbuffers::Vector<uint8_t>* fb_param_types,
    const flatbuffers::Vector<flatbuffers::Offset<void>>* fb_params)
{
    daemon::common::RequestParameters parameters;

    if (!fb_param_types || !fb_params || fb_param_types->size() != fb_params->size())
    {
        return parameters;
    }

    for (size_t i = 0; i < fb_param_types->size(); ++i)
    {
        auto param_type = fb_param_types->Get(i);
        const auto* fb_param = fb_params->Get(i);

        if (!fb_param)
            continue;

        switch (static_cast<score::crypto::ipc::control::OperationParameter>(param_type))
        {
            case score::crypto::ipc::control::OperationParameter_NoParam:
            {
                parameters.emplace_back(daemon::control_plane::protocol::NoParam{});
                break;
            }
            case score::crypto::ipc::control::OperationParameter_ValueBool:
            {
                const auto* fb_val =
                    static_cast<const score::crypto::ipc::control::ValueBool*>(static_cast<const void*>(fb_param));
                if (fb_val)
                {
                    parameters.emplace_back(bool{fb_val->val()});
                }
                break;
            }
            case score::crypto::ipc::control::OperationParameter_ValueUint8:
            {
                const auto* fb_val =
                    static_cast<const score::crypto::ipc::control::ValueUint8*>(static_cast<const void*>(fb_param));
                if (fb_val)
                {
                    parameters.emplace_back(std::uint8_t{fb_val->val()});
                }
                break;
            }
            case score::crypto::ipc::control::OperationParameter_ValueUint16:
            {
                const auto* fb_val =
                    static_cast<const score::crypto::ipc::control::ValueUint16*>(static_cast<const void*>(fb_param));
                if (fb_val)
                {
                    parameters.emplace_back(std::uint16_t{fb_val->val()});
                }
                break;
            }
            case score::crypto::ipc::control::OperationParameter_ValueUint32:
            {
                const auto* fb_val =
                    static_cast<const score::crypto::ipc::control::ValueUint32*>(static_cast<const void*>(fb_param));
                if (fb_val)
                {
                    parameters.emplace_back(std::uint32_t{fb_val->val()});
                }
                break;
            }
            case score::crypto::ipc::control::OperationParameter_ValueUint64:
            {
                const auto* fb_val =
                    static_cast<const score::crypto::ipc::control::ValueUint64*>(static_cast<const void*>(fb_param));
                if (fb_val)
                {
                    parameters.emplace_back(std::uint64_t{fb_val->val()});
                }
                break;
            }
            case score::crypto::ipc::control::OperationParameter_String:
            {
                const auto* fb_string =
                    static_cast<const score::crypto::ipc::control::String*>(static_cast<const void*>(fb_param));
                if (fb_string && fb_string->val())
                {
                    parameters.emplace_back(std::string_view{fb_string->val()->c_str(), fb_string->val()->size()});
                }
                break;
            }
            case score::crypto::ipc::control::OperationParameter_DataBufferInBand:
            {
                const auto* fb_buffer = static_cast<const score::crypto::ipc::control::DataBufferInBand*>(
                    static_cast<const void*>(fb_param));
                if (fb_buffer && fb_buffer->val())
                {
                    // Zero-copy: borrow from FlatBuffer memory (alive for RPC duration)
                    const auto* fb_data = fb_buffer->val();
                    parameters.emplace_back(daemon::common::VirtualMemoryBufferConst{fb_data->data(), fb_data->size()});
                }
                break;
            }
            case score::crypto::ipc::control::OperationParameter_DataBufferDataPlane:
            case score::crypto::ipc::control::OperationParameter_NONE:
            default:
            {
                // TODO: Not all types of the varaint are implemented. However all
                // which are currently used are implemented.
                // In case we end up here, we may need to implemented serialization / deserializazion
                // for the concrete type.

                score::mw::log::LogError() << "[GrpcControlServiceAdapter] ERROR - Unsupported parameter type: "
                                           << static_cast<int>(param_type);
                break;
            }
        }
    }

    return parameters;
}

}  // namespace score::crypto::ipc

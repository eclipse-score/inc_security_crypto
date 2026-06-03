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

#include "score/crypto/ipc/grpc_adapter/grpc_control_client.h"
#include "score/crypto/common/types.hpp"
#include "score/crypto/daemon/common/types.hpp"
#include "score/crypto/daemon/control_plane/control_protocol.h"
#include "score/crypto/ipc/grpc_adapter/control.grpc.fb.h"
#include "score/crypto/ipc/grpc_adapter/control_generated.h"
#include "score/crypto/ipc/grpc_adapter/src/grpc_id_helpers.h"

#include "flatbuffers/grpc.h"
#include <grpcpp/grpcpp.h>

#include "score/mw/log/logging.h"
#include <cstddef>
#include <cstdint>

#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

namespace score::crypto::ipc
{

// PIMPL implementation - hides grpc types from public header
struct GrpcControlClient::Impl
{
    std::unique_ptr<score::crypto::ipc::control::ControlService::Stub>
        stub;  // NOLINT(misc-non-private-member-variables-in-classes)

    explicit Impl(std::string_view socket_path)
    {
        auto channel = grpc::CreateChannel("unix:" + std::string(socket_path), grpc::InsecureChannelCredentials());
        stub = score::crypto::ipc::control::ControlService::NewStub(channel);
    }

    flatbuffers::grpc::Message<score::crypto::ipc::control::ControlRequest> ConvertRequest(
        const daemon::control_plane::protocol::ControlRequest& bl_req,
        flatbuffers::grpc::MessageBuilder& mb);

    daemon::control_plane::protocol::ControlResponse ConvertResponse(
        const score::crypto::ipc::control::ControlResponse* fb_resp);

    static daemon::common::ResponseParameters ExtractResponseParameters(
        const flatbuffers::Vector<uint8_t>* fb_param_types,
        const flatbuffers::Vector<flatbuffers::Offset<void>>* fb_params);

    static std::pair<std::vector<uint8_t>, std::vector<::flatbuffers::Offset<void>>> BuildRequestParameters(
        const daemon::common::RequestParameters& bl_params,
        flatbuffers::grpc::MessageBuilder& mb);
};

GrpcControlClient::GrpcControlClient(std::string_view socket_path) : _impl(std::make_unique<Impl>(socket_path)) {}

GrpcControlClient::~GrpcControlClient() = default;

Expected<daemon::control_plane::protocol::ControlResponse, score::mw::crypto::CryptoErrorCode>
GrpcControlClient::SendRequest(const daemon::control_plane::protocol::ControlRequest& request)
{
    // TODO: Avoid copy
    auto enhanced_request = request;
    enhanced_request.request_id = RequestId::getRequestId();
    enhanced_request.uid = InsecureClientId::getUid();
    enhanced_request.pid = InsecureClientId::getPid();

    // Convert business logic request → FlatBuffer
    flatbuffers::grpc::MessageBuilder mb;
    auto fb_request = _impl->ConvertRequest(enhanced_request, mb);

    // Send gRPC call
    grpc::ClientContext context;
    flatbuffers::grpc::Message<score::crypto::ipc::control::ControlResponse> fb_response;

    const grpc::Status status = _impl->stub->Execute(&context, fb_request, &fb_response);

    if (!status.ok())
    {
        std::ostringstream tid;
        tid << std::this_thread::get_id();
        score::mw::log::LogError() << "[GrpcControlClient] [Thread" << tid.str() << "] "
                                   << "gRPC call failed for RequestID:" << request.request_id
                                   << " | Error:" << status.error_message();
        return make_unexpected(score::mw::crypto::CryptoErrorCode::kInternalError);
    }
    // Convert FlatBuffer response → business logic
    auto response = _impl->ConvertResponse(fb_response.GetRoot());

    if (enhanced_request.request_id != response.request_id)
    {
        score::mw::log::LogError() << " [MISMATCH!] RequestID mismatch - received: ";
        return make_unexpected(score::mw::crypto::CryptoErrorCode::kInternalError);
    }

    return response;
}

daemon::control_plane::protocol::DataNodeId GrpcControlClient::GetConnectionNodeId() const
{
    // GrpcControlClient is a pure transport implementation managed by ConnectionImpl.
    // The connection node ID is stored in ConnectionImpl, not here.
    // Return 0 to indicate no ID is set at this level.
    return 0;
}

flatbuffers::grpc::Message<score::crypto::ipc::control::ControlRequest> GrpcControlClient::Impl::ConvertRequest(
    const daemon::control_plane::protocol::ControlRequest& bl_req,
    flatbuffers::grpc::MessageBuilder& mb)
{
    // Build operation request batch
    std::vector<::flatbuffers::Offset<score::crypto::ipc::control::SingleOperationRequest>> fb_single_requests;

    for (const auto& bl_single_req : bl_req.operation.operations)
    {
        // Build operation identifier
        auto fb_op_id = score::crypto::ipc::control::CreateOperationIdentifier(
            mb, bl_single_req.operationId.operationActor, bl_single_req.operationId.operationAction);

        // Build request parameters
        auto [fb_param_types, fb_params] = BuildRequestParameters(bl_single_req.parameters, mb);

        // Create parameter vectors
        auto fb_param_types_vec = mb.CreateVector(fb_param_types);
        auto fb_params_vec = mb.CreateVector(fb_params);

        // Build single operation request
        auto fb_single_req =
            score::crypto::ipc::control::CreateSingleOperationRequest(mb, fb_op_id, fb_param_types_vec, fb_params_vec);

        fb_single_requests.push_back(fb_single_req);
    }

    // Create operation request batch
    auto fb_op_batch =
        score::crypto::ipc::control::CreateOperationRequestBatch(mb, mb.CreateVector(fb_single_requests));

    // Build ControlRequest
    auto fb_request = score::crypto::ipc::control::CreateControlRequest(
        mb, bl_req.request_id, bl_req.client_id, bl_req.data_node_id, fb_op_batch);

    // Finish the request and return as Message
    mb.Finish(fb_request);
    return mb.GetMessage<score::crypto::ipc::control::ControlRequest>();
}

daemon::control_plane::protocol::ControlResponse GrpcControlClient::Impl::ConvertResponse(
    const score::crypto::ipc::control::ControlResponse* fb_resp)
{
    // Create a new ControlResponse with extracted data from FlatBuffer
    daemon::control_plane::protocol::ControlResponse bl_resp{};

    // Extract scalar fields
    bl_resp.request_id = fb_resp->request_id();

    // Extract operation batch
    const auto* fb_op_batch = fb_resp->operation_batch();
    if (fb_op_batch && fb_op_batch->operations())
    {
        // Iterate over each SingleOperationResponse in the batch
        for (const auto* fb_single_resp : *fb_op_batch->operations())
        {
            if (!fb_single_resp)
                continue;

            // Create a SingleOperationResponse in business logic
            daemon::control_plane::protocol::SingleOperationResponse bl_single_resp{};

            // Extract operation identifier
            const auto* fb_op_id = fb_single_resp->operation_id();
            if (fb_op_id)
            {
                bl_single_resp.operationId.operationActor = fb_op_id->operation_actor();
                bl_single_resp.operationId.operationAction = fb_op_id->operation_action();
            }

            // Extract operation result
            const auto* fb_result = fb_single_resp->result();
            if (fb_result)
            {
                bl_single_resp.result = static_cast<daemon::control_plane::protocol::OperationResult>(fb_result->val());
            }

            // Extract response parameters
            bl_single_resp.parameters =
                ExtractResponseParameters(fb_single_resp->parameter_type(), fb_single_resp->parameter());

            // Add the single operation to the batch
            bl_resp.operation.operations.push_back(bl_single_resp);
        }
    }

    return bl_resp;
}

daemon::common::ResponseParameters GrpcControlClient::Impl::ExtractResponseParameters(
    const flatbuffers::Vector<uint8_t>* fb_param_types,
    const flatbuffers::Vector<flatbuffers::Offset<void>>* fb_params)
{
    daemon::common::ResponseParameters parameters;

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
                    parameters.emplace_back(daemon::control_plane::protocol::OwnedString(fb_string->val()->c_str()));
                }
                break;
            }
            case score::crypto::ipc::control::OperationParameter_DataBufferInBand:
            {
                const auto* fb_buffer = static_cast<const score::crypto::ipc::control::DataBufferInBand*>(
                    static_cast<const void*>(fb_param));
                if (fb_buffer && fb_buffer->val())
                {
                    // Copy FlatBuffer byte vector into a std::vector (must own - FB goes out of scope)
                    const auto* fb_data = fb_buffer->val();
                    daemon::control_plane::protocol::OwnedBuffer data_copy(fb_data->begin(), fb_data->end());
                    parameters.emplace_back(std::move(data_copy));
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

                score::mw::log::LogError()
                    << "[GrpcControlClient] ERROR - Unsupported parameter type:" << static_cast<int>(param_type);
                break;
            }
        }
    }

    return parameters;
}

std::pair<std::vector<uint8_t>, std::vector<::flatbuffers::Offset<void>>>
GrpcControlClient::Impl::BuildRequestParameters(const daemon::common::RequestParameters& bl_params,
                                                flatbuffers::grpc::MessageBuilder& mb)
{
    std::vector<uint8_t> fb_param_types;
    std::vector<::flatbuffers::Offset<void>> fb_params;

    for (const auto& bl_param : bl_params)
    {
        if (std::holds_alternative<daemon::control_plane::protocol::NoParam>(bl_param))
        {
            fb_param_types.emplace_back(score::crypto::ipc::control::OperationParameter_NoParam);
            auto fb_no_param = score::crypto::ipc::control::CreateNoParam(mb);
            fb_params.emplace_back(fb_no_param.o);
        }
        else if (std::holds_alternative<bool>(bl_param))
        {
            const auto& val = std::get<bool>(bl_param);
            fb_param_types.emplace_back(score::crypto::ipc::control::OperationParameter_ValueBool);
            auto fb_val = score::crypto::ipc::control::CreateValueBool(mb, val);
            fb_params.emplace_back(fb_val.o);
        }
        else if (std::holds_alternative<std::string_view>(bl_param))
        {
            const auto& str = std::get<std::string_view>(bl_param);
            fb_param_types.emplace_back(score::crypto::ipc::control::OperationParameter_String);
            auto fb_str_offset = mb.CreateString(str);
            auto fb_string = score::crypto::ipc::control::CreateString(mb, fb_str_offset);
            fb_params.emplace_back(fb_string.o);
        }
        else if (std::holds_alternative<daemon::common::VirtualMemoryBufferConst>(bl_param))
        {
            const auto& buffer = std::get<daemon::common::VirtualMemoryBufferConst>(bl_param);
            fb_param_types.emplace_back(score::crypto::ipc::control::OperationParameter_DataBufferInBand);
            auto fb_data = mb.CreateVector(buffer.data, buffer.size);
            auto fb_buffer = score::crypto::ipc::control::CreateDataBufferInBand(mb, fb_data);
            fb_params.emplace_back(fb_buffer.o);
        }
        else if (std::holds_alternative<daemon::common::VirtualMemoryBuffer>(bl_param))
        {
            const auto& buffer = std::get<daemon::common::VirtualMemoryBuffer>(bl_param);
            fb_param_types.emplace_back(score::crypto::ipc::control::OperationParameter_DataBufferInBand);
            auto fb_data = mb.CreateVector(buffer.data, buffer.size);
            auto fb_buffer = score::crypto::ipc::control::CreateDataBufferInBand(mb, fb_data);
            fb_params.emplace_back(fb_buffer.o);
        }
        else if (std::holds_alternative<std::uint8_t>(bl_param))
        {
            const auto& val = std::get<std::uint8_t>(bl_param);
            fb_param_types.emplace_back(score::crypto::ipc::control::OperationParameter_ValueUint8);
            auto fb_val = score::crypto::ipc::control::CreateValueUint8(mb, val);
            fb_params.emplace_back(fb_val.o);
        }
        else if (std::holds_alternative<std::uint16_t>(bl_param))
        {
            const auto& val = std::get<std::uint16_t>(bl_param);
            fb_param_types.emplace_back(score::crypto::ipc::control::OperationParameter_ValueUint16);
            auto fb_val = score::crypto::ipc::control::CreateValueUint16(mb, val);
            fb_params.emplace_back(fb_val.o);
        }
        else if (std::holds_alternative<std::uint32_t>(bl_param))
        {
            const auto& val = std::get<std::uint32_t>(bl_param);
            fb_param_types.emplace_back(score::crypto::ipc::control::OperationParameter_ValueUint32);
            auto fb_val = score::crypto::ipc::control::CreateValueUint32(mb, val);
            fb_params.emplace_back(fb_val.o);
        }
        else if (std::holds_alternative<std::uint64_t>(bl_param))
        {
            const auto& val = std::get<std::uint64_t>(bl_param);
            fb_param_types.emplace_back(score::crypto::ipc::control::OperationParameter_ValueUint64);
            auto fb_val = score::crypto::ipc::control::CreateValueUint64(mb, val);
            fb_params.emplace_back(fb_val.o);
        }
        else
        {
            // TODO: Not all types of the varaint are implemented. However all
            // which are currently used are implemented.
            // In case we end up here, we may need to implemented serialization / deserializazion
            // for the concrete type.

            score::mw::log::LogError() << "[GrpcControlClient] ERROR - Unsupported parameter type in request";
            // Skip unsupported parameter types
            continue;
        }
    }

    return {fb_param_types, fb_params};
}

}  // namespace score::crypto::ipc

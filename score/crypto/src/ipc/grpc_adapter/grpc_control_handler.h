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

// Renamed from grpc_adapter.h to grpc_handler.h
// Renamed from grpc_handler.h to grpc_control_handler.h
#ifndef GRPC_CONTROL_HANDLER_H
#define GRPC_CONTROL_HANDLER_H

#include "score/crypto/daemon/control_plane/control_protocol.h"
#include "score/crypto/daemon/control_plane/i_handler_chain_factory.hpp"
#include "score/crypto/ipc/grpc_adapter/control.grpc.fb.h"
#include <grpcpp/grpcpp.h>
#include <memory>

namespace score::crypto::ipc
{

class GrpcControlServiceAdapter final : public score::crypto::ipc::control::ControlService::Service
{
  public:
    explicit GrpcControlServiceAdapter(
        std::unique_ptr<score::crypto::daemon::control_plane::IHandlerChainFactory> factory);

    grpc::Status Execute(grpc::ServerContext* context,
                         const flatbuffers::grpc::Message<score::crypto::ipc::control::ControlRequest>* request,
                         flatbuffers::grpc::Message<score::crypto::ipc::control::ControlResponse>* response) override;

  private:
    std::unique_ptr<score::crypto::daemon::control_plane::IHandlerChainFactory> _factory;

    // Thread-local handler instance (one per gRPC worker thread)
    static thread_local std::unique_ptr<daemon::control_plane::IRequestHandler> _thread_handler;

    // Convert FlatBuffer message to business logic struct
    daemon::control_plane::protocol::ControlRequest ConvertRequest(
        const score::crypto::ipc::control::ControlRequest* fb_req);

    // Extract request parameters from FlatBuffer format
    static daemon::common::RequestParameters ExtractRequestParameters(
        const flatbuffers::Vector<uint8_t>* fb_param_types,
        const flatbuffers::Vector<flatbuffers::Offset<void>>* fb_params);

    // Convert business logic struct to FlatBuffer message
    void ConvertResponse(const daemon::control_plane::protocol::ControlResponse& bl_resp,
                         flatbuffers::grpc::Message<score::crypto::ipc::control::ControlResponse>* fb_resp);

    // Build response parameters into FlatBuffer format
    static std::pair<std::vector<uint8_t>, std::vector<::flatbuffers::Offset<void>>> BuildResponseParameters(
        const daemon::common::ResponseParameters& bl_params,
        flatbuffers::grpc::MessageBuilder& builder);
};

}  // namespace score::crypto::ipc

#endif  // GRPC_CONTROL_HANDLER_H

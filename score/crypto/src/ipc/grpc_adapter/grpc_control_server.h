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

#ifndef GRPC_CONTROL_SERVER_H
#define GRPC_CONTROL_SERVER_H

#include <memory>
#include <string_view>

#include "score/crypto/daemon/control_plane/i_control_server.h"
#include "score/crypto/daemon/control_plane/i_handler_chain_factory.hpp"

namespace score::crypto::ipc
{

// gRPC implementation of IControlServer
// Manages server lifecycle and socket cleanup
class GrpcControlServer final : public daemon::control_plane::IControlServer
{
  public:
    explicit GrpcControlServer(std::unique_ptr<daemon::control_plane::IHandlerChainFactory> factory);
    ~GrpcControlServer() override;

    // Disable copy and move
    GrpcControlServer(const GrpcControlServer&) = delete;
    GrpcControlServer& operator=(const GrpcControlServer&) = delete;
    GrpcControlServer(GrpcControlServer&&) = delete;
    GrpcControlServer& operator=(GrpcControlServer&&) = delete;

    // IControlServer implementation
    void Start(std::string_view socket_path) override;
    void Stop() override;
    void WaitForTermination() override;

  private:
    struct Impl;
    std::unique_ptr<Impl> _impl;
};

}  // namespace score::crypto::ipc

#endif  // GRPC_CONTROL_SERVER_H

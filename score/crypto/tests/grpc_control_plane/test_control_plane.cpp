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

#include <gtest/gtest.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#include "score/crypto/api/control_plane/connection_factory.hpp"
#include "score/crypto/daemon/common/actors.hpp"
#include "score/crypto/daemon/config/inc/config.hpp"
#include "score/crypto/daemon/control_plane/control_protocol.h"
#include "score/crypto/daemon/control_plane/src/connection_handler.hpp"
#include "score/crypto/daemon/data_manager/data_manager.hpp"
#include "score/crypto/ipc/grpc_adapter/grpc_control_server.h"
#include "score/mw/crypto/api/common/error_domain.hpp"

// namespace aliases
namespace api = score::crypto::api;
namespace control_plane = score::crypto::daemon::control_plane;
namespace ipc = score::crypto::ipc;

namespace score::crypto::test
{
daemon::common::OperationActor dummyActorA = 0;
daemon::common::OperationActor dummyActorB = 1;
daemon::common::OperationAction dummyActionA = 0;
daemon::common::OperationAction dummyActionB = 1;

std::uint64_t dummyReturnParameter = 12345;
std::string dummyStringParameter = "testData";

// Dummy handler node in chain - processes operations and returns proper responses
// Terminal handler (no next handler in test chain)
class DummyRequestHandlerNode : public score::crypto::daemon::control_plane::IRequestHandler
{
  public:
    DummyRequestHandlerNode() = default;

    score::crypto::daemon::control_plane::protocol::ControlResponse processRequest(
        const score::crypto::daemon::control_plane::protocol::ControlRequest& request) override
    {
        score::crypto::daemon::control_plane::protocol::ControlResponse response;
        response.request_id = request.request_id;

        // Terminal handler - process operations and build proper responses
        auto responseBuilder = score::crypto::daemon::control_plane::protocol::OperationResponseBuilder();

        for (const auto& op : request.operation.operations)
        {
            const auto& opId = op.operationId;

            if (opId.operationActor == dummyActorA && opId.operationAction == dummyActionA)
            {
                if (op.parameters.size() != 2)
                {
                    responseBuilder.operation(opId).return_error(score::mw::crypto::CryptoErrorCode::kInternalError);
                    continue;
                }

                auto paramRes = op.getParameter<std::string_view>(0);
                if (!paramRes.has_value())
                {
                    responseBuilder.operation(opId).return_error(score::mw::crypto::CryptoErrorCode::kInternalError);
                    continue;
                }
                auto paramValue = paramRes.value();
                if (paramValue != dummyStringParameter)
                {
                    responseBuilder.operation(opId).return_error(score::mw::crypto::CryptoErrorCode::kInternalError);
                    continue;
                }

                auto noParamRes = op.getParameter<score::crypto::daemon::control_plane::protocol::NoParam>(1);
                if (!noParamRes.has_value())
                {
                    responseBuilder.operation(opId).return_error(score::mw::crypto::CryptoErrorCode::kInternalError);
                    continue;
                }

                responseBuilder.operation(opId).return_success().return_value_uint64(dummyReturnParameter);
            }
            else
            {
                responseBuilder.operation(opId).return_error(score::mw::crypto::CryptoErrorCode::kInternalError);
            }
        }

        response.operation = responseBuilder.build().value();
        return response;
    }
};

// Test factory implementation for creating handler chains in tests
class TestRequestHandlerFactory : public score::crypto::daemon::control_plane::IHandlerChainFactory
{
  public:
    TestRequestHandlerFactory(std::shared_ptr<score::crypto::daemon::data_manager::IDataManager> data_manager,
                              const score::crypto::daemon::config::Config& config)
        : m_data_manager(std::move(data_manager)), m_config(config)
    {
    }

    std::unique_ptr<score::crypto::daemon::control_plane::IRequestHandler> CreateRequestHandler() override
    {
        // Create a fresh dummy handler for each request
        auto dummy_handler = std::make_unique<DummyRequestHandlerNode>();
        return std::make_unique<score::crypto::daemon::control_plane::ConnectionHandler>(
            std::move(dummy_handler), m_data_manager, m_config);
    }

  private:
    std::shared_ptr<score::crypto::daemon::data_manager::IDataManager> m_data_manager;
    const score::crypto::daemon::config::Config& m_config;
};

}  // namespace score::crypto::test

class ControlPlaneTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        // Namespace alias to avoid conflicts with unistd.h daemon() function
        namespace ipc = score::crypto::ipc;

        // Generate unique socket path for this test
        _socket_path = "/tmp/test_crypto_" + std::to_string(getpid()) + "_" +
                       std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".sock";

        // Create default config for testing
        score::crypto::daemon::config::Config config;

        // Create data manager
        auto data_manager = std::make_shared<score::crypto::daemon::data_manager::DataManager>();

        // Create test factory that produces ConnectionHandler wrappers with fresh dummy nodes per thread
        auto test_factory = std::make_unique<score::crypto::test::TestRequestHandlerFactory>(data_manager, config);

        // Create gRPC server with factory (server will create ConnectionHandler wrappers per thread)
        _server = std::make_unique<ipc::GrpcControlServer>(std::move(test_factory));

        // Start gRPC server in background thread
        _server_thread = std::thread([this]() {
            _server->Start(_socket_path);
            _server->WaitForTermination();
        });

        // Give server time to start
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    void TearDown() override
    {
        if (_server)
        {
            _server->Stop();
        }

        if (_server_thread.joinable())
        {
            _server_thread.join();
        }
    }

    std::string _socket_path;
    std::unique_ptr<score::crypto::ipc::GrpcControlServer> _server;
    std::thread _server_thread;
};

TEST_F(ControlPlaneTest, Connection_SendRequest)
{
    auto endpoint = "unix://" + _socket_path;
    auto connection_res = api::control_plane::ConnectionFactory().CreateConnection(endpoint);
    ASSERT_TRUE(connection_res.has_value());
    auto connection = std::move(connection_res).value();

    // Create context with algorithm first
    auto controlRequest = score::crypto::daemon::control_plane::protocol::ControlRequestBuilder()
                              .forDataNodeId(0)
                              .operation({score::crypto::test::dummyActorA, score::crypto::test::dummyActionA})
                              .with_in_string("testData")
                              .with_no_param()
                              .build();

    if (!controlRequest.has_value())
    {
        ASSERT_TRUE(false) << "Failed to build control request";
    }

    auto dummyResponseResult = connection->SendRequest(controlRequest.value());
    ASSERT_TRUE(dummyResponseResult.has_value());

    auto dummyResponse = std::move(dummyResponseResult).value();
    ASSERT_EQ(dummyResponse.operation.operations.size(), 1);
    ASSERT_EQ(dummyResponse.operation.operations[0].operationId.operationActor, score::crypto::test::dummyActorA);
    ASSERT_EQ(dummyResponse.operation.operations[0].operationId.operationAction, score::crypto::test::dummyActionA);
    ASSERT_EQ(dummyResponse.operation.operations[0].result,
              score::crypto::daemon::control_plane::protocol::OPERATION_RESULT_SUCCESS);
    ASSERT_EQ(dummyResponse.operation.operations[0].parameters.size(), 1);
    auto returnParameterRes = dummyResponse.operation.operations[0].getParameter<std::uint64_t>(0);
    ASSERT_TRUE(returnParameterRes.has_value());
    auto returnParameter = returnParameterRes.value();
    ASSERT_EQ(returnParameter, score::crypto::test::dummyReturnParameter);
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

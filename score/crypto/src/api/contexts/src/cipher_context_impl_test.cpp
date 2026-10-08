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

#include "score/crypto/src/api/contexts/src/cipher_context_impl.hpp"

#include "score/crypto/src/api/control_plane/i_connection.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/provider/handler/operations/cipher_handler_operations.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <variant>
#include <vector>

namespace score::crypto
{
namespace
{

namespace proto = ::score::crypto::daemon::control_plane::protocol;
namespace actors = ::score::crypto::daemon::common::actors;
namespace cipher_ops = ::score::crypto::daemon::provider::handler::cipher_handler_operations;

constexpr std::uint64_t kContextId = 42U;
constexpr proto::OperationIdentifier kGetMaxOutputSize{actors::OP_ACTOR_CIPHER_HANDLER,
                                                       cipher_ops::CIPHER_GET_MAX_OUTPUT_SIZE};

/// Records every request and answers each with the same canned response.
class FakeConnection final : public api::control_plane::IConnection
{
  public:
    Expected<proto::ControlResponse, CryptoErrorCode> SendRequest(const proto::ControlRequest& request) override
    {
        requests.push_back(request);
        return response;
    }

    proto::DataNodeId GetConnectionNodeId() const override
    {
        return 0U;
    }

    std::vector<proto::ControlRequest> requests;
    Expected<proto::ControlResponse, CryptoErrorCode> response{make_unexpected(CryptoErrorCode::kInternalError)};
};

proto::ControlResponse MakeResponse(proto::OperationResult result,
                                    ::score::crypto::daemon::common::ResponseParameters parameters)
{
    proto::ControlResponse response{};
    response.operation.operations.push_back(proto::SingleOperationResponse{kGetMaxOutputSize, result, parameters});
    return response;
}

class CipherContextImplMaxOutputSizeTest : public ::testing::Test
{
  protected:
    std::shared_ptr<FakeConnection> connection_{std::make_shared<FakeConnection>()};
    CipherContextImpl cipher_{connection_, kContextId, "AES-256-CBC"};
};

TEST_F(CipherContextImplMaxOutputSizeTest, SendsInputLengthAndReturnsDaemonBound)
{
    connection_->response = MakeResponse(proto::OPERATION_RESULT_SUCCESS, {std::uint64_t{21U}});

    const auto size = cipher_.GetMaximumOutputSize(5U);

    ASSERT_TRUE(size.has_value());
    EXPECT_EQ(size.value(), 21U);

    ASSERT_EQ(connection_->requests.size(), 1U);
    const auto& request = connection_->requests.front();
    EXPECT_EQ(request.data_node_id, kContextId);
    ASSERT_EQ(request.operation.operations.size(), 1U);
    const auto& operation = request.operation.operations.front();
    EXPECT_EQ(operation.operationId.operationActor, kGetMaxOutputSize.operationActor);
    EXPECT_EQ(operation.operationId.operationAction, kGetMaxOutputSize.operationAction);
    ASSERT_EQ(operation.parameters.size(), 1U);
    const auto* const input_size = std::get_if<std::uint64_t>(&operation.parameters.front());
    ASSERT_NE(input_size, nullptr);
    EXPECT_EQ(*input_size, 5U);
}

TEST_F(CipherContextImplMaxOutputSizeTest, ConnectionFailureIsAnError)
{
    connection_->response = make_unexpected(CryptoErrorCode::kInternalError);

    EXPECT_FALSE(cipher_.GetMaximumOutputSize(5U).has_value());
}

TEST_F(CipherContextImplMaxOutputSizeTest, DaemonErrorIsAnError)
{
    connection_->response =
        MakeResponse(static_cast<proto::OperationResult>(CryptoErrorCode::kUnsupportedAlgorithm), {});

    EXPECT_FALSE(cipher_.GetMaximumOutputSize(5U).has_value());
}

TEST_F(CipherContextImplMaxOutputSizeTest, MistypedResponseParameterIsAnError)
{
    connection_->response = MakeResponse(proto::OPERATION_RESULT_SUCCESS, {std::uint32_t{21U}});

    EXPECT_FALSE(cipher_.GetMaximumOutputSize(5U).has_value());
}

}  // namespace
}  // namespace score::crypto

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

#include "score/crypto/api/control_plane/connection_factory.hpp"
#include "score/crypto/api/control_plane/i_connection.hpp"
#include "score/crypto/common/types.hpp"
#include "score/crypto/daemon/common/actors.hpp"
#include "score/crypto/daemon/control_plane/control_operations.h"
#include "score/crypto/daemon/control_plane/control_protocol.h"
#include "score/crypto/daemon/mediator/mediator_operations.hpp"
#include "score/crypto/daemon/provider/handler/operations/hash_handler_operations.hpp"
#include "score/crypto/ipc/ipc_config.h"
#include "score/mw/crypto/api/common/error_domain.hpp"
#include <gtest/gtest.h>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <vector>

namespace score::crypto::test
{

// Simple barrier implementation for synchronizing threads
class Barrier
{
  public:
    explicit Barrier(int count) : threshold_(count), count_(count), generation_(0) {}

    void Wait()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        int gen = generation_;
        if (--count_ == 0)
        {
            generation_++;
            count_ = threshold_;
            cv_.notify_all();
        }
        else
        {
            cv_.wait(lock, [this, gen] {
                return gen != generation_;
            });
        }
    }

  private:
    std::mutex mutex_;
    std::condition_variable cv_;
    int threshold_;
    int count_;
    int generation_;
};

// ============================================================================
// Helper functions for common operations
// ============================================================================

/// Create a control plane connection and open a connection on the daemon
inline score::crypto::Expected<std::pair<std::unique_ptr<api::control_plane::IConnection>, std::uint64_t>,
                               score::mw::crypto::CryptoErrorCode>
CreateConnectionWithOpen()
{
    auto endpoint = "unix://" + std::string(score::crypto::ipc::kControlSocket);
    api::control_plane::ConnectionFactory factory;
    auto connResult = factory.CreateConnection(endpoint);

    if (!connResult.has_value())
    {
        return score::crypto::make_unexpected(score::mw::crypto::CryptoErrorCode::kInvalidArgument);
    }

    auto connection = std::move(connResult.value());

    // Send CONNECTION_OPEN to the daemon
    auto connOpenResponse = daemon::control_plane::protocol::ControlRequestBuilder()
                                .forDataNodeId(0)
                                .operation(daemon::control_plane::operations::OpenConnection())
                                .build();

    if (!connOpenResponse.has_value())
    {
        return score::crypto::make_unexpected(score::mw::crypto::CryptoErrorCode::kInternalError);
    }

    auto connOpenResponseRes = connection->SendRequest(connOpenResponse.value());
    auto connOpenValidator = daemon::control_plane::protocol::ControlResponseValidator::FromResult(connOpenResponseRes);

    if (!connOpenValidator.isValid())
    {
        return score::crypto::make_unexpected(score::mw::crypto::CryptoErrorCode::kInternalError);
    }

    connOpenValidator.expectOperation(daemon::control_plane::operations::OpenConnection()).expectSuccess();

    if (!connOpenValidator.isValid())
    {
        return score::crypto::make_unexpected(score::mw::crypto::CryptoErrorCode::kInternalError);
    }

    auto connId = connOpenValidator.getParameterAt<std::uint64_t>(0, 0);
    if (!connId.has_value())
    {
        return score::crypto::make_unexpected(score::mw::crypto::CryptoErrorCode::kInternalError);
    }

    return std::make_pair(std::move(connection), connId.value());
}

/// Create a context and return the context_id
inline score::crypto::Expected<std::uint64_t, score::mw::crypto::CryptoErrorCode>
CreateContext(api::control_plane::IConnection* connection, std::uint64_t connection_id, const std::string& algorithm)
{
    auto ctxResponse = daemon::control_plane::protocol::ControlRequestBuilder()
                           .forDataNodeId(connection_id)
                           .operation(daemon::mediator::operations::CreateContext())
                           .with_in_string("HASH")
                           .with_in_string(algorithm)
                           .build();

    if (!ctxResponse.has_value())
    {
        return score::crypto::make_unexpected(score::mw::crypto::CryptoErrorCode::kContextCreationFailed);
    }

    auto ctxResponseRes = connection->SendRequest(ctxResponse.value());
    auto ctxValidator = daemon::control_plane::protocol::ControlResponseValidator::FromResult(ctxResponseRes);

    if (!ctxValidator.isValid())
    {
        return score::crypto::make_unexpected(score::mw::crypto::CryptoErrorCode::kContextCreationFailed);
    }

    ctxValidator.expectOperation(daemon::mediator::operations::CreateContext()).expectSuccess();

    if (!ctxValidator.isValid())
    {
        return score::crypto::make_unexpected(score::mw::crypto::CryptoErrorCode::kContextCreationFailed);
    }

    auto ctxId = ctxValidator.getParameterAt<std::uint64_t>(0, 0);
    if (!ctxId.has_value())
    {
        return score::crypto::make_unexpected(score::mw::crypto::CryptoErrorCode::kInvalidArgument);
    }

    return ctxId.value();
}

/// Close a context
inline bool CloseContext(api::control_plane::IConnection* connection, std::uint64_t context_id)
{
    auto closeCtxResponse = daemon::control_plane::protocol::ControlRequestBuilder()
                                .forDataNodeId(context_id)
                                .operation(daemon::mediator::operations::CloseContext())
                                .build();

    if (!closeCtxResponse.has_value())
    {
        return false;
    }

    auto closeCtxResponseRes = connection->SendRequest(closeCtxResponse.value());
    auto closeCtxValidator = daemon::control_plane::protocol::ControlResponseValidator::FromResult(closeCtxResponseRes);

    if (!closeCtxValidator.isValid())
    {
        return false;
    }

    closeCtxValidator.expectOperation(daemon::mediator::operations::CloseContext()).expectSuccess();

    return closeCtxValidator.isValid();
}

/// Close a connection
inline bool CloseConnection(api::control_plane::IConnection* connection, std::uint64_t connection_id)
{
    auto closeConnResponse = daemon::control_plane::protocol::ControlRequestBuilder()
                                 .forDataNodeId(connection_id)
                                 .operation(daemon::control_plane::operations::CloseConnection())
                                 .build();

    if (!closeConnResponse.has_value())
    {
        return false;
    }

    auto closeConnResponseRes = connection->SendRequest(closeConnResponse.value());
    auto closeConnValidator =
        daemon::control_plane::protocol::ControlResponseValidator::FromResult(closeConnResponseRes);

    return closeConnValidator.isValid();
}

// Parameterized test data structure
struct HashTestData
{
    std::string algorithm;
    std::string input_data;
    std::vector<uint8_t> expected_hash;
    size_t expected_size;

    std::string GetTestName() const
    {
        std::string name = algorithm + "_" + input_data;
        // Replace all non-alphanumeric characters (except underscore) with underscore
        for (auto& c : name)
        {
            if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_')
            {
                c = '_';
            }
        }
        // Handle empty input_data case
        if (input_data.empty())
        {
            name = algorithm + "_empty_string";
        }
        return name;
    }
};

class ParameterizedHashTest : public ::testing::TestWithParam<HashTestData>
{
  protected:
    void SetUp() override
    {
        auto conn_result = CreateConnectionWithOpen();
        ASSERT_TRUE(conn_result.has_value()) << "Failed to create connection";
        auto pair = std::move(conn_result).value();
        _connection = std::move(pair.first);
        _connection_id = pair.second;
    }

    std::unique_ptr<api::control_plane::IConnection> _connection;
    std::uint64_t _connection_id;
};

TEST_P(ParameterizedHashTest, HashWithDifferentAlgorithmsAndData)
{
    auto test_data = GetParam();

    // 1. Create context with CTX_CREATE and specify algorithm
    auto ctxIdRes = CreateContext(_connection.get(), _connection_id, test_data.algorithm);
    ASSERT_TRUE(ctxIdRes.has_value()) << "Failed to create context";
    uint64_t context_id = ctxIdRes.value();
    std::cout << "Created context with context_id: " << context_id << " using algorithm: " << test_data.algorithm
              << std::endl;

    // 2. Prepare input data for hashing
    std::vector<uint8_t> inputBuffer(test_data.input_data.begin(), test_data.input_data.end());

    // 3. Build HASH_SS operation request with context_id and data
    auto operationResponse = daemon::control_plane::protocol::ControlRequestBuilder()
                                 .forDataNodeId(context_id)
                                 .operation({daemon::common::actors::OP_ACTOR_HASH_HANDLER,
                                             daemon::provider::handler::hash_handler_operations::HASH_SS})
                                 .with_in_data_buffer(inputBuffer)
                                 .build();

    if (!operationResponse.has_value())
    {
        // Close the context first, then assert
        CloseContext(_connection.get(), context_id);
        ASSERT_TRUE(false) << "Failed to build HASH_SS request";
    }

    // Request operation through the connection
    auto responseRes = _connection->SendRequest(operationResponse.value());
    auto hashValidator = daemon::control_plane::protocol::ControlResponseValidator::FromResult(responseRes);
    ASSERT_TRUE(hashValidator.isValid()) << hashValidator.getError();

    hashValidator
        .expectOperation({daemon::common::actors::OP_ACTOR_HASH_HANDLER,
                          daemon::provider::handler::hash_handler_operations::HASH_SS})
        .expectSuccess();

    ASSERT_TRUE(hashValidator.isValid()) << hashValidator.getError();

    auto hashOutput = hashValidator.getParameterAt<daemon::control_plane::protocol::DataBufferReturn>(0, 0);
    ASSERT_TRUE(hashOutput.has_value()) << "Failed to extract hash output from response";

    ASSERT_EQ(hashOutput.value().size(), test_data.expected_size)
        << test_data.algorithm << " should produce " << test_data.expected_size << " bytes";

    // Verify hash matches expected value
    ASSERT_EQ(hashOutput.value(), test_data.expected_hash)
        << "Hash output does not match expected " << test_data.algorithm << " for '" << test_data.input_data << "'";

    // 4. Close the context
    ASSERT_TRUE(CloseContext(_connection.get(), context_id)) << "Failed to close context";

    // 5. Close the connection
    ASSERT_TRUE(CloseConnection(_connection.get(), _connection_id)) << "Failed to close connection";
}

INSTANTIATE_TEST_SUITE_P(
    HashAlgorithmsAndData,
    ParameterizedHashTest,
    ::testing::Values(
        // SHA256 test cases
        HashTestData{"SHA256",
                     "Hello, World!",
                     {0xdf, 0xfd, 0x60, 0x21, 0xbb, 0x2b, 0xd5, 0xb0, 0xaf, 0x67, 0x62, 0x90, 0x80, 0x9e, 0xc3, 0xa5,
                      0x31, 0x91, 0xdd, 0x81, 0xc7, 0xf7, 0x0a, 0x4b, 0x28, 0x68, 0x8a, 0x36, 0x21, 0x82, 0x98, 0x6f},
                     32},
        HashTestData{"SHA256",
                     "Hello S-Core",  // Empty string
                     {0xcf, 0x4a, 0x68, 0x50, 0x44, 0x51, 0x2f, 0xbc, 0xb1, 0x08, 0xeb, 0x37, 0x25, 0x48, 0x5b, 0x61,
                      0x02, 0x6f, 0x7d, 0xb4, 0x2b, 0x70, 0xef, 0x78, 0xee, 0x4f, 0x96, 0x96, 0x23, 0x17, 0x45, 0x25},
                     32},
        HashTestData{"SHA256",
                     "The quick brown fox jumps over the lazy dog",
                     {0xd7, 0xa8, 0xfb, 0xb3, 0x07, 0xd7, 0x80, 0x94, 0x69, 0xca, 0x9a, 0xbc, 0xb0, 0x08, 0x2e, 0x4f,
                      0x8d, 0x56, 0x51, 0xe4, 0x6d, 0x3c, 0xdb, 0x76, 0x2d, 0x02, 0xd0, 0xbf, 0x37, 0xc9, 0xe5, 0x92},
                     32},
        // SHA512 test cases
        HashTestData{"SHA512",
                     "Hello, World!",
                     {0x37, 0x4d, 0x79, 0x4a, 0x95, 0xcd, 0xcf, 0xd8, 0xb3, 0x59, 0x93, 0x18, 0x5f, 0xef, 0x9b, 0xa3,
                      0x68, 0xf1, 0x60, 0xd8, 0xda, 0xf4, 0x32, 0xd0, 0x8b, 0xa9, 0xf1, 0xed, 0x1e, 0x5a, 0xbe, 0x6c,
                      0xc6, 0x92, 0x91, 0xe0, 0xfa, 0x2f, 0xe0, 0x00, 0x6a, 0x52, 0x57, 0x0e, 0xf1, 0x8c, 0x19, 0xde,
                      0xf4, 0xe6, 0x17, 0xc3, 0x3c, 0xe5, 0x2e, 0xf0, 0xa6, 0xe5, 0xfb, 0xe3, 0x18, 0xcb, 0x03, 0x87},
                     64}),
    [](const ::testing::TestParamInfo<HashTestData>& info) {
        return info.param.GetTestName();
    });

class ParameterizedHashStreamingTest : public ::testing::TestWithParam<HashTestData>
{
  protected:
    void SetUp() override
    {
        auto conn_result = CreateConnectionWithOpen();
        ASSERT_TRUE(conn_result.has_value()) << "Failed to create connection";
        auto pair = std::move(conn_result).value();
        _connection = std::move(pair.first);
        _connection_id = pair.second;
    }

    std::unique_ptr<api::control_plane::IConnection> _connection;
    std::uint64_t _connection_id;
};

TEST_P(ParameterizedHashStreamingTest, StreamingHashWithDifferentAlgorithmsAndData)
{
    auto test_data = GetParam();

    // 1. Create context with CTX_CREATE and specify algorithm
    auto ctxIdRes = CreateContext(_connection.get(), _connection_id, test_data.algorithm);
    ASSERT_TRUE(ctxIdRes.has_value()) << "Failed to create context";
    uint64_t context_id = ctxIdRes.value();
    std::cout << "Created context with context_id: " << context_id << " using algorithm: " << test_data.algorithm
              << std::endl;

    // 2. HASH_INIT - no algorithm parameter needed anymore
    auto initResponse = daemon::control_plane::protocol::ControlRequestBuilder()
                            .forDataNodeId(context_id)
                            .operation({daemon::common::actors::OP_ACTOR_HASH_HANDLER,
                                        daemon::provider::handler::hash_handler_operations::HASH_INIT})
                            .build();

    if (!initResponse.has_value())
    {
        CloseContext(_connection.get(), context_id);
        ASSERT_TRUE(false) << "Failed to build HASH_INIT request";
    }

    auto initResponseRes = _connection->SendRequest(initResponse.value());
    auto initValidator = daemon::control_plane::protocol::ControlResponseValidator::FromResult(initResponseRes);
    ASSERT_TRUE(initValidator.isValid()) << initValidator.getError();

    initValidator
        .expectOperation({daemon::common::actors::OP_ACTOR_HASH_HANDLER,
                          daemon::provider::handler::hash_handler_operations::HASH_INIT})
        .expectSuccess();
    ASSERT_TRUE(initValidator.isValid()) << initValidator.getError();

    // 3. HASH_UPDATE (split data into two parts)
    size_t split_point = test_data.input_data.size() / 2;
    std::string data1_str = test_data.input_data.substr(0, split_point);
    std::string data2_str = test_data.input_data.substr(split_point);

    std::vector<uint8_t> data1(data1_str.begin(), data1_str.end());
    auto updateResponse1 = daemon::control_plane::protocol::ControlRequestBuilder()
                               .forDataNodeId(context_id)
                               .operation({daemon::common::actors::OP_ACTOR_HASH_HANDLER,
                                           daemon::provider::handler::hash_handler_operations::HASH_UPDATE})
                               .with_in_data_buffer(data1)
                               .build();

    if (!updateResponse1.has_value())
    {
        CloseContext(_connection.get(), context_id);
        ASSERT_TRUE(false) << "Failed to build HASH_UPDATE (1) request";
    }

    auto updateResponseRes1 = _connection->SendRequest(updateResponse1.value());
    auto updateValidator1 = daemon::control_plane::protocol::ControlResponseValidator::FromResult(updateResponseRes1);
    ASSERT_TRUE(updateValidator1.isValid()) << updateValidator1.getError();

    updateValidator1
        .expectOperation({daemon::common::actors::OP_ACTOR_HASH_HANDLER,
                          daemon::provider::handler::hash_handler_operations::HASH_UPDATE})
        .expectSuccess();
    ASSERT_TRUE(updateValidator1.isValid()) << updateValidator1.getError();

    // 4. HASH_UPDATE (part 2)
    std::vector<uint8_t> data2(data2_str.begin(), data2_str.end());
    auto updateResponse2 = daemon::control_plane::protocol::ControlRequestBuilder()
                               .forDataNodeId(context_id)
                               .operation({daemon::common::actors::OP_ACTOR_HASH_HANDLER,
                                           daemon::provider::handler::hash_handler_operations::HASH_UPDATE})
                               .with_in_data_buffer(data2)
                               .build();

    if (!updateResponse2.has_value())
    {
        CloseContext(_connection.get(), context_id);
        ASSERT_TRUE(false) << "Failed to build HASH_UPDATE (2) request";
    }

    auto updateResponseRes2 = _connection->SendRequest(updateResponse2.value());
    auto updateValidator2 = daemon::control_plane::protocol::ControlResponseValidator::FromResult(updateResponseRes2);
    ASSERT_TRUE(updateValidator2.isValid()) << updateValidator2.getError();

    updateValidator2
        .expectOperation({daemon::common::actors::OP_ACTOR_HASH_HANDLER,
                          daemon::provider::handler::hash_handler_operations::HASH_UPDATE})
        .expectSuccess();
    ASSERT_TRUE(updateValidator2.isValid()) << updateValidator2.getError();

    // 5. HASH_FINALIZE
    auto finishResponse = daemon::control_plane::protocol::ControlRequestBuilder()
                              .forDataNodeId(context_id)
                              .operation({daemon::common::actors::OP_ACTOR_HASH_HANDLER,
                                          daemon::provider::handler::hash_handler_operations::HASH_FINALIZE})
                              .build();

    if (!finishResponse.has_value())
    {
        CloseContext(_connection.get(), context_id);
        ASSERT_TRUE(false) << "Failed to build HASH_FINALIZE request";
    }

    auto finishResponseRes = _connection->SendRequest(finishResponse.value());
    auto finishValidator = daemon::control_plane::protocol::ControlResponseValidator::FromResult(finishResponseRes);
    ASSERT_TRUE(finishValidator.isValid()) << finishValidator.getError();

    finishValidator
        .expectOperation({daemon::common::actors::OP_ACTOR_HASH_HANDLER,
                          daemon::provider::handler::hash_handler_operations::HASH_FINALIZE})
        .expectSuccess();

    ASSERT_TRUE(finishValidator.isValid()) << finishValidator.getError();

    // 6. Verify hash output
    auto hashOutput = finishValidator.getParameterAt<daemon::control_plane::protocol::DataBufferReturn>(0, 0);
    ASSERT_TRUE(hashOutput.has_value());
    ASSERT_EQ(hashOutput.value().size(), test_data.expected_size)
        << test_data.algorithm << " should produce " << test_data.expected_size << " bytes";

    ASSERT_EQ(hashOutput.value(), test_data.expected_hash)
        << "Hash output does not match expected " << test_data.algorithm << " for '" << test_data.input_data << "'";

    // 7. Close the context
    ASSERT_TRUE(CloseContext(_connection.get(), context_id)) << "Failed to close context";
    std::cout << "Closed context with context_id: " << context_id << std::endl;

    // 8. Close the connection
    ASSERT_TRUE(CloseConnection(_connection.get(), _connection_id)) << "Failed to close connection";
}

INSTANTIATE_TEST_SUITE_P(
    HashStreamingAlgorithmsAndData,
    ParameterizedHashStreamingTest,
    ::testing::Values(
        // SHA256 test cases
        HashTestData{"SHA256",
                     "Hello, World!",
                     {0xdf, 0xfd, 0x60, 0x21, 0xbb, 0x2b, 0xd5, 0xb0, 0xaf, 0x67, 0x62, 0x90, 0x80, 0x9e, 0xc3, 0xa5,
                      0x31, 0x91, 0xdd, 0x81, 0xc7, 0xf7, 0x0a, 0x4b, 0x28, 0x68, 0x8a, 0x36, 0x21, 0x82, 0x98, 0x6f},
                     32},
        HashTestData{"SHA256",
                     "Hello S-Core",
                     {0xcf, 0x4a, 0x68, 0x50, 0x44, 0x51, 0x2f, 0xbc, 0xb1, 0x08, 0xeb, 0x37, 0x25, 0x48, 0x5b, 0x61,
                      0x02, 0x6f, 0x7d, 0xb4, 0x2b, 0x70, 0xef, 0x78, 0xee, 0x4f, 0x96, 0x96, 0x23, 0x17, 0x45, 0x25},
                     32},
        // SHA512 test cases
        HashTestData{"SHA512",
                     "Hello, World!",
                     {0x37, 0x4d, 0x79, 0x4a, 0x95, 0xcd, 0xcf, 0xd8, 0xb3, 0x59, 0x93, 0x18, 0x5f, 0xef, 0x9b, 0xa3,
                      0x68, 0xf1, 0x60, 0xd8, 0xda, 0xf4, 0x32, 0xd0, 0x8b, 0xa9, 0xf1, 0xed, 0x1e, 0x5a, 0xbe, 0x6c,
                      0xc6, 0x92, 0x91, 0xe0, 0xfa, 0x2f, 0xe0, 0x00, 0x6a, 0x52, 0x57, 0x0e, 0xf1, 0x8c, 0x19, 0xde,
                      0xf4, 0xe6, 0x17, 0xc3, 0x3c, 0xe5, 0x2e, 0xf0, 0xa6, 0xe5, 0xfb, 0xe3, 0x18, 0xcb, 0x03, 0x87},
                     64}),
    [](const ::testing::TestParamInfo<HashTestData>& info) {
        return info.param.GetTestName();
    });

class ParallelRequests : public ::testing::TestWithParam<int>
{
  protected:
    void SetUp() override
    {
        auto conn_result = CreateConnectionWithOpen();
        ASSERT_TRUE(conn_result.has_value()) << "Failed to create connection";
        auto pair = std::move(conn_result).value();
        _connection = std::move(pair.first);
        _connection_id = pair.second;
    }

    std::unique_ptr<api::control_plane::IConnection> _connection;
    std::uint64_t _connection_id;
};

TEST_P(ParallelRequests, ParallelDummyRequests)
{
    const int num_threads = GetParam();
    std::vector<std::thread> threads;
    threads.reserve(num_threads);

    Barrier sync_barrier(num_threads);
    // std::vector<bool> is not sufficient here.
    // It does not guarantee proper concurrent access to individual elements from different threads.
    std::vector<int> success_flags(num_threads, 0);

    for (int i = 0; i < num_threads; ++i)
    {
        threads.emplace_back([i, &sync_barrier, &success_flags]() {
            // Create a connection for this thread
            auto conn_result = CreateConnectionWithOpen();

            if (!conn_result.has_value())
            {
                success_flags[i] = 0;
                return;
            }
            auto pair = std::move(conn_result).value();
            auto connection = std::move(pair.first);
            auto connection_id = pair.second;

            // Wait for all threads to be ready
            sync_barrier.Wait();

            // Send request
            daemon::control_plane::protocol::ControlRequest request;
            request.data_node_id = connection_id;

            // Verify response
            auto response = connection->SendRequest(request);
            success_flags[i] = response.has_value() ? 1 : 0;
        });
    }

    // Wait for all threads to complete
    for (auto& thread : threads)
    {
        thread.join();
    }

    // Verify all requests succeeded
    for (int i = 0; i < num_threads; ++i)
    {
        EXPECT_NE(success_flags[i], 0) << "Thread " << i << " failed";
    }
}

INSTANTIATE_TEST_SUITE_P(ThreadCounts, ParallelRequests, ::testing::Values(16));

}  // namespace score::crypto::test

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

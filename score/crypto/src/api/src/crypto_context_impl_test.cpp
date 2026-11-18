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

#include "score/crypto/src/api/src/crypto_context_impl.hpp"
#include "score/crypto/src/api/config/base_context_config.hpp"
#include "score/crypto/src/api/crypto_stack_factory.hpp"
#include "score/crypto/src/api/src/crypto_context_impl.hpp"

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/config/hash_context_config.hpp"
#include "score/crypto/src/api/contexts/i_hash_context.hpp"
#include "score/crypto/src/api/control_plane/i_connection.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>

namespace score::crypto
{
namespace
{

namespace protocol = daemon::control_plane::protocol;

class ErrorConnection final : public api::control_plane::IConnection
{
  public:
    explicit ErrorConnection(const CryptoErrorCode error_code) : m_error_code{error_code} {}

    Expected<protocol::ControlResponse, CryptoErrorCode> SendRequest(protocol::ControlRequest& /*request*/) override
    {
        ++m_request_count;
        protocol::ControlResponse response{};
        response.operations.push_back(protocol::SingleOperationResponse{
            daemon::mediator::operations::CreateContext(), static_cast<protocol::OperationResult>(m_error_code), {}});
        return response;
    }

    Expected<protocol::ControlResponse, CryptoErrorCode> SendRequest(protocol::ControlRequest& request,
                                                                     std::chrono::milliseconds timeout) override
    {
        return SendRequest(request);
    }

    protocol::DataNodeId GetConnectionNodeId() const override
    {
        return 1U;
    }

    std::size_t GetRequestCount() const noexcept
    {
        return m_request_count;
    }

  private:
    CryptoErrorCode m_error_code;
    std::size_t m_request_count{0U};
};

TEST(CryptoContextImplTest, PreservesHashContextCreationErrorFromDaemon)
{
    auto connection = std::make_shared<ErrorConnection>(CryptoErrorCode::kUnsupportedAlgorithm);
    CryptoContextImpl context{connection, nullptr};

    HashContextConfig config;
    config.SetAlgorithm("UNSUPPORTED_ALGORITHM");
    const auto result = context.CreateHashContext(config);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(*result.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kUnsupportedAlgorithm));
}

TEST(CryptoContextImplTest, RejectsExplicitHashProviderInsteadOfIgnoringIt)
{
    auto connection = std::make_shared<ErrorConnection>(CryptoErrorCode::kInternalError);
    CryptoContextImpl context{connection, nullptr};

    const CryptoResourceId provider{42U, ResourceType::kProvider, ResourcePersistence::kEphemeral, 0U};

    HashContextConfig config;
    config.SetAlgorithm("SHA256").SetProvider(provider);
    const auto result = context.CreateHashContext(config);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(*result.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kUnsupportedOperation));
    EXPECT_EQ(connection->GetRequestCount(), 0U);
}

TEST(CryptoStackConfigTest, SetDefaultOperationTimeoutClampsNonPositiveValues)
{
    CryptoStackConfig config;

    config.SetDefaultOperationTimeout(std::chrono::milliseconds{0});
    ASSERT_TRUE(config.default_operation_timeout.has_value());
    EXPECT_EQ(config.default_operation_timeout.value(), std::chrono::milliseconds{1});

    config.SetDefaultOperationTimeout(std::chrono::milliseconds{-1});
    EXPECT_EQ(config.default_operation_timeout.value(), std::chrono::milliseconds{1});
}

TEST(CryptoStackConfigTest, ResolutionClampsDirectlyAssignedNonPositiveDefault)
{
    CryptoStackConfig config;
    config.default_operation_timeout = std::chrono::milliseconds{0};
    EXPECT_EQ(ResolveOperationTimeout(true, std::nullopt, config.default_operation_timeout),
              std::chrono::milliseconds{1});

    config.default_operation_timeout = std::chrono::milliseconds{-1};
    EXPECT_EQ(ResolveOperationTimeout(true, std::nullopt, config.default_operation_timeout),
              std::chrono::milliseconds{1});
}

}  // namespace
}  // namespace score::crypto

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

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/config/hash_context_config.hpp"
#include "score/crypto/src/api/contexts/i_hash_context.hpp"
#include "score/crypto/src/api/control_plane/i_connection.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>

namespace score::crypto
{
namespace
{

namespace protocol = daemon::control_plane::protocol;

class ErrorConnection final : public api::control_plane::IConnection
{
  public:
    explicit ErrorConnection(const CryptoErrorCode error_code) : m_error_code{error_code} {}

    Expected<protocol::ControlResponse, CryptoErrorCode> SendRequest(
        const protocol::ControlRequest& /*request*/) override
    {
        protocol::ControlResponse response{};
        response.operation.operations.push_back(protocol::SingleOperationResponse{
            daemon::mediator::operations::CreateContext(), static_cast<protocol::OperationResult>(m_error_code), {}});
        return response;
    }

    protocol::DataNodeId GetConnectionNodeId() const override
    {
        return 1U;
    }

  private:
    CryptoErrorCode m_error_code;
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

}  // namespace
}  // namespace score::crypto

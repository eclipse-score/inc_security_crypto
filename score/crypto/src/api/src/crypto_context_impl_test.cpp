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
#include "score/crypto/src/api/config/cipher_context_config.hpp"
#include "score/crypto/src/api/config/hash_context_config.hpp"
#include "score/crypto/src/api/config/mac_context_config.hpp"
#include "score/crypto/src/api/config/sign_context_config.hpp"
#include "score/crypto/src/api/config/verify_signature_context_config.hpp"
#include "score/crypto/src/api/contexts/i_cipher_context.hpp"
#include "score/crypto/src/api/contexts/i_hash_context.hpp"
#include "score/crypto/src/api/contexts/i_mac_context.hpp"
#include "score/crypto/src/api/contexts/i_sign_context.hpp"
#include "score/crypto/src/api/contexts/i_verify_signature_context.hpp"
#include "score/crypto/src/api/control_plane/i_connection.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"

#include <gtest/gtest.h>

#include <cstddef>
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
        ++m_request_count;
        protocol::ControlResponse response{};
        response.operation.operations.push_back(protocol::SingleOperationResponse{
            daemon::mediator::operations::CreateContext(), static_cast<protocol::OperationResult>(m_error_code), {}});
        return response;
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

    CryptoResourceId provider{};
    provider.id = 42U;
    provider.type = ResourceType::kProvider;

    HashContextConfig config;
    config.SetAlgorithm("SHA256").SetProvider(provider);
    const auto result = context.CreateHashContext(config);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(*result.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kUnsupportedOperation));
    EXPECT_EQ(connection->GetRequestCount(), 0U);
}

TEST(CryptoContextImplTest, RejectsSharedSecretsForKeyedOperationContextsBeforeIpc)
{
    const std::shared_ptr<ErrorConnection> connection =
        std::make_shared<ErrorConnection>(CryptoErrorCode::kInternalError);
    CryptoContextImpl context{connection, nullptr};
    const CryptoResourceId secret{71U, ResourceType::kSharedSecret, ResourcePersistence::kEphemeral, 3U};
    CipherContextConfig cipher{};
    cipher.SetAlgorithm("AES-256-GCM").SetKey(secret);
    MacContextConfig mac{};
    mac.SetAlgorithm("HMAC-SHA256").SetKey(secret);
    SignContextConfig sign{};
    sign.SetAlgorithm("ML-DSA-44").SetKey(secret);
    VerifySignatureContextConfig verify{};
    verify.SetAlgorithm("ML-DSA-44").SetKey(secret);

    const score::Result<std::unique_ptr<ICipherContext>> cipher_result = context.CreateCipherContext(cipher);
    const score::Result<std::unique_ptr<IMacContext>> mac_result = context.CreateMacContext(mac);
    const score::Result<std::unique_ptr<ISignContext>> sign_result = context.CreateSignContext(sign);
    const score::Result<std::unique_ptr<IVerifySignatureContext>> verify_result =
        context.CreateVerifySignatureContext(verify);

    ASSERT_FALSE(cipher_result.has_value());
    ASSERT_FALSE(mac_result.has_value());
    ASSERT_FALSE(sign_result.has_value());
    ASSERT_FALSE(verify_result.has_value());
    const score::result::Error unsupported = MakeError(CryptoErrorCode::kUnsupportedOperation);
    EXPECT_EQ(cipher_result.error(), unsupported);
    EXPECT_EQ(mac_result.error(), unsupported);
    EXPECT_EQ(sign_result.error(), unsupported);
    EXPECT_EQ(verify_result.error(), unsupported);
    EXPECT_EQ(connection->GetRequestCount(), 0U);
}

}  // namespace
}  // namespace score::crypto

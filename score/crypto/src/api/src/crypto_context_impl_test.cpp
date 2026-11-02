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
#include "score/crypto/src/api/config/key_management_context_config.hpp"
#include "score/crypto/src/api/config/key_operation_params.hpp"
#include "score/crypto/src/api/config/mac_context_config.hpp"
#include "score/crypto/src/api/config/random_context_config.hpp"
#include "score/crypto/src/api/config/sign_context_config.hpp"
#include "score/crypto/src/api/config/verify_signature_context_config.hpp"
#include "score/crypto/src/api/contexts/i_cipher_context.hpp"
#include "score/crypto/src/api/contexts/i_hash_context.hpp"
#include "score/crypto/src/api/contexts/i_key_management_context.hpp"
#include "score/crypto/src/api/contexts/i_mac_context.hpp"
#include "score/crypto/src/api/contexts/i_random_context.hpp"
#include "score/crypto/src/api/contexts/i_sign_context.hpp"
#include "score/crypto/src/api/contexts/i_verify_signature_context.hpp"
#include "score/crypto/src/api/contexts/src/key_management_context_impl.hpp"
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

    // A catalog name passes the client check; the daemon may still refuse it.
    HashContextConfig config;
    config.SetAlgorithm("SHA256");
    const auto result = context.CreateHashContext(config);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(*result.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kUnsupportedAlgorithm));
    EXPECT_EQ(connection->GetRequestCount(), 1U);
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

// ---------------------------------------------------------------------------
// Client-side algorithm check: unknown names never reach the daemon
// ---------------------------------------------------------------------------

constexpr auto kUnsupportedAlgorithm = static_cast<score::result::ErrorCode>(CryptoErrorCode::kUnsupportedAlgorithm);

CryptoResourceId TestKey()
{
    CryptoResourceId key{};
    key.id = 7U;
    key.type = ResourceType::kKey;
    return key;
}

class ClientAlgorithmCheckTest : public ::testing::Test
{
  protected:
    // Any request that does reach the transport fails with an error other
    // than kUnsupportedAlgorithm, so the two outcomes cannot be confused.
    std::shared_ptr<ErrorConnection> m_connection{std::make_shared<ErrorConnection>(CryptoErrorCode::kInternalError)};
    CryptoContextImpl m_context{m_connection, nullptr};
};

TEST_F(ClientAlgorithmCheckTest, RefusesUnknownNamesForEveryAlgorithmContextWithoutIpc)
{
    const auto check = [this](const auto& result) {
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(*result.error(), kUnsupportedAlgorithm);
    };

    check(m_context.CreateHashContext(HashContextConfig{}.SetAlgorithm("SHA-256")));
    check(m_context.CreateMacContext(MacContextConfig{}.SetAlgorithm("HMAC-SHA-256").SetKey(TestKey())));
    check(m_context.CreateCipherContext(CipherContextConfig{}.SetAlgorithm("AES-256-XTS").SetKey(TestKey())));
    check(m_context.CreateSignContext(SignContextConfig{}.SetAlgorithm("ML-DSA-65").SetKey(TestKey())));
    check(m_context.CreateVerifySignatureContext(
        VerifySignatureContextConfig{}.SetAlgorithm("ECDSA-P256-SHA1").SetKey(TestKey())));
    check(m_context.CreateRandomContext(RandomContextConfig{}.SetAlgorithm("HMAC-DRBG")));
    // An empty name is not a catalog name either, except for RANDOM (below).
    check(m_context.CreateHashContext(HashContextConfig{}));

    EXPECT_EQ(m_connection->GetRequestCount(), 0U);
}

TEST_F(ClientAlgorithmCheckTest, RefusesEnumeratorWithoutCatalogRowWithoutIpc)
{
    const auto hash = m_context.CreateHashContext(HashContextConfig{}.SetAlgorithm(Algorithm::kUnknown));
    ASSERT_FALSE(hash.has_value());
    EXPECT_EQ(*hash.error(), kUnsupportedAlgorithm);

    // Not taken for the empty name that selects the default generator.
    const auto random = m_context.CreateRandomContext(RandomContextConfig{}.SetAlgorithm(Algorithm::kUnknown));
    ASSERT_FALSE(random.has_value());
    EXPECT_EQ(*random.error(), kUnsupportedAlgorithm);

    EXPECT_EQ(m_connection->GetRequestCount(), 0U);
}

TEST_F(ClientAlgorithmCheckTest, SendsCatalogNamesToTheDaemon)
{
    const auto result =
        m_context.CreateSignContext(SignContextConfig{}.SetAlgorithm(Algorithm::kEcdsaP521Sha224).SetKey(TestKey()));
    ASSERT_FALSE(result.has_value());
    EXPECT_NE(*result.error(), kUnsupportedAlgorithm);
    EXPECT_EQ(m_connection->GetRequestCount(), 1U);
}

TEST_F(ClientAlgorithmCheckTest, EmptyRandomAlgorithmIsSentLikeTheDaemonAcceptsIt)
{
    // The daemon reads an empty RANDOM algorithm as CTR-DRBG.
    const auto result = m_context.CreateRandomContext(RandomContextConfig{});
    ASSERT_FALSE(result.has_value());
    EXPECT_NE(*result.error(), kUnsupportedAlgorithm);
    EXPECT_EQ(m_connection->GetRequestCount(), 1U);
}

TEST_F(ClientAlgorithmCheckTest, KeyManagementContextCarriesNoAlgorithmAndIsNotChecked)
{
    const auto result = m_context.CreateKeyManagementContext(KeyManagementContextConfig{});
    ASSERT_FALSE(result.has_value());
    EXPECT_NE(*result.error(), kUnsupportedAlgorithm);
    EXPECT_EQ(m_connection->GetRequestCount(), 1U);
}

TEST(KeyManagementAlgorithmCheckTest, RefusesUnknownKeyAlgorithmsWithoutIpc)
{
    auto connection = std::make_shared<ErrorConnection>(CryptoErrorCode::kInternalError);
    {
        KeyManagementContextImpl context{connection, 1U};
        CryptoResourceId slot{};
        slot.id = 3U;
        slot.type = ResourceType::kKeySlot;

        const auto generated = context.GenerateKey(GenerateKeyParams{}.SetAlgorithm("AES-512"));
        ASSERT_FALSE(generated.has_value());
        EXPECT_EQ(*generated.error(), kUnsupportedAlgorithm);

        const auto typed = context.GenerateKey(GenerateKeyParams{}.SetAlgorithm(Algorithm::kUnknown));
        ASSERT_FALSE(typed.has_value());
        EXPECT_EQ(*typed.error(), kUnsupportedAlgorithm);

        const auto into_slot = context.GenerateKey(slot, std::nullopt, GenerateKeyParams{}.SetAlgorithm("RSA-1024"));
        ASSERT_FALSE(into_slot.has_value());
        EXPECT_EQ(*into_slot.error(), kUnsupportedAlgorithm);

        const auto imported = context.ImportKey(ImportKeyParams{}.SetAlgorithm("HMAC-SHA-256"));
        ASSERT_FALSE(imported.has_value());
        EXPECT_EQ(*imported.error(), kUnsupportedAlgorithm);

        const auto imported_to_slot = context.ImportKey(slot, ImportKeyParams{}.SetAlgorithm(""));
        ASSERT_FALSE(imported_to_slot.has_value());
        EXPECT_EQ(*imported_to_slot.error(), kUnsupportedAlgorithm);

        EXPECT_EQ(connection->GetRequestCount(), 0U);

        // A catalog name is sent.
        const auto known = context.GenerateKey(GenerateKeyParams{}.SetAlgorithm(Algorithm::kHmacSha256));
        ASSERT_FALSE(known.has_value());
        EXPECT_NE(*known.error(), kUnsupportedAlgorithm);
        EXPECT_EQ(connection->GetRequestCount(), 1U);
    }
}

}  // namespace
}  // namespace score::crypto

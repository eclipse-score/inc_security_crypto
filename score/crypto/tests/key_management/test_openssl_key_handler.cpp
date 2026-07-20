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

#include "score/crypto/daemon/key_management/interfaces/i_key_factory.hpp"
#include "score/crypto/daemon/provider/score_provider/openssl/key_management/openssl_key_factory.hpp"
#include "score/crypto/daemon/provider/score_provider/openssl/key_management/openssl_key_handler.hpp"
#include "score/mw/crypto/api/common/types.hpp"

#include <gtest/gtest.h>
#include <cstring>

namespace km = score::crypto::daemon::key_management;
namespace common = score::crypto::daemon::common;

class OpenSslKeyHandlerTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        m_factory =
            std::make_shared<score::crypto::daemon::provider::openssl::OpenSslKeyFactory>(0);  // OPENSSL provider ID
    }

    std::shared_ptr<score::crypto::daemon::provider::openssl::OpenSslKeyFactory> m_factory;
};

// ============================================================================
// GenerateKey tests
// ============================================================================

TEST_F(OpenSslKeyHandlerTest, GenerateKey_HmacSha256_Returns32ByteKey)
{
    km::KeyGenerationRequest req{};
    req.algorithm = "HMAC-SHA256";
    req.permissions = score::mw::crypto::KeyOperationPermission::kMac;

    auto result = m_factory->GenerateKey(req);

    ASSERT_TRUE(result.has_value());
    auto& handler = result.value();
    auto& handle = handler->GetHandle();
    EXPECT_NE(handle.opaque_id, 0U);
    EXPECT_EQ(handle.key_size, 32U);
    EXPECT_EQ(handle.algorithm, "HMAC-SHA256");
    EXPECT_FALSE(handle.is_asymmetric);
    EXPECT_FALSE(
        score::mw::crypto::HasPermission(handle.permissions, score::mw::crypto::KeyOperationPermission::kExport));

    // Cleanup
    auto release = handler->Release();
    EXPECT_TRUE(release.has_value());
}

TEST_F(OpenSslKeyHandlerTest, GenerateKey_HmacSha512_Returns64ByteKey)
{
    km::KeyGenerationRequest req{};
    req.algorithm = "HMAC-SHA512";
    req.permissions =
        score::mw::crypto::KeyOperationPermission::kMac | score::mw::crypto::KeyOperationPermission::kExport;

    auto result = m_factory->GenerateKey(req);

    ASSERT_TRUE(result.has_value());
    auto& handler = result.value();
    EXPECT_EQ(handler->GetHandle().key_size, 64U);
    EXPECT_TRUE(score::mw::crypto::HasPermission(handler->GetHandle().permissions,
                                                 score::mw::crypto::KeyOperationPermission::kExport));

    auto release = handler->Release();
    EXPECT_TRUE(release.has_value());
}

TEST_F(OpenSslKeyHandlerTest, GenerateKey_Aes256_Returns32ByteKey)
{
    km::KeyGenerationRequest req{};
    req.algorithm = "AES-256-CBC";
    req.permissions = score::mw::crypto::KeyOperationPermission::kEncrypt;

    auto result = m_factory->GenerateKey(req);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value()->GetHandle().key_size, 32U);

    auto release = result.value()->Release();
    EXPECT_TRUE(release.has_value());
}

TEST_F(OpenSslKeyHandlerTest, GenerateKey_UnknownAlgorithm_ReturnsError)
{
    km::KeyGenerationRequest req{};
    req.algorithm = "UNKNOWN-ALGO";
    req.permissions = score::mw::crypto::KeyOperationPermission::kMac;

    auto result = m_factory->GenerateKey(req);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
}

// ============================================================================
// ImportKey tests
// ============================================================================

TEST_F(OpenSslKeyHandlerTest, ImportKey_ValidKey_Succeeds)
{
    const uint8_t raw_key[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
                                 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
                                 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};

    km::KeyImportRequest req{};
    req.key_data = raw_key;
    req.key_data_size = sizeof(raw_key);
    req.algorithm = "HMAC-SHA256";
    req.permissions = score::mw::crypto::KeyOperationPermission::kMac;

    auto result = m_factory->ImportKey(req);

    ASSERT_TRUE(result.has_value());
    auto& handler = result.value();
    EXPECT_NE(handler->GetHandle().opaque_id, 0U);
    EXPECT_EQ(handler->GetHandle().key_size, 32U);

    // Verify key comes from the correct provider
    ASSERT_EQ(handler->GetProviderId(), 0);  // OPENSSL provider ID
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast)
    const auto* openssl_handler =
        static_cast<const score::crypto::daemon::provider::openssl::OpenSslKeyHandler*>(handler.get());
    std::size_t out_size = 0;
    const auto* key_bytes = openssl_handler->GetRawKeyBytes(out_size);
    ASSERT_NE(key_bytes, nullptr);
    EXPECT_EQ(out_size, 32U);
    EXPECT_EQ(std::memcmp(key_bytes, raw_key, 32U), 0);

    auto release = handler->Release();
    EXPECT_TRUE(release.has_value());
}

TEST_F(OpenSslKeyHandlerTest, ImportKey_NullPointer_ReturnsError)
{
    km::KeyImportRequest req{};
    req.key_data = nullptr;
    req.key_data_size = 32;
    req.algorithm = "HMAC-SHA256";
    req.permissions = score::mw::crypto::KeyOperationPermission::kMac;

    auto result = m_factory->ImportKey(req);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
}

TEST_F(OpenSslKeyHandlerTest, ImportKey_ZeroSize_ReturnsError)
{
    const uint8_t dummy = 0;
    km::KeyImportRequest req{};
    req.key_data = &dummy;
    req.key_data_size = 0;
    req.algorithm = "HMAC-SHA256";
    req.permissions = score::mw::crypto::KeyOperationPermission::kMac;

    auto result = m_factory->ImportKey(req);

    ASSERT_FALSE(result.has_value());
}

// ============================================================================
// ReleaseKey tests
// ============================================================================

TEST_F(OpenSslKeyHandlerTest, ReleaseKey_ZeroOpaque_Idempotent)
{
    // Create a handler via GenerateKey and test that Release is idempotent
    km::KeyGenerationRequest req{};
    req.algorithm = "HMAC-SHA256";
    req.permissions = score::mw::crypto::KeyOperationPermission::kMac;

    auto gen_result = m_factory->GenerateKey(req);
    ASSERT_TRUE(gen_result.has_value());

    auto& handler = gen_result.value();
    auto release1 = handler->Release();
    ASSERT_TRUE(release1.has_value());

    // Second Release should also succeed (idempotent)
    auto release2 = handler->Release();
    ASSERT_TRUE(release2.has_value());
}

TEST_F(OpenSslKeyHandlerTest, GenerateAndRelease_FullLifecycle)
{
    km::KeyGenerationRequest req{};
    req.algorithm = "HMAC-SHA256";
    req.permissions = score::mw::crypto::KeyOperationPermission::kMac;

    auto gen_result = m_factory->GenerateKey(req);
    ASSERT_TRUE(gen_result.has_value());

    auto release_result = gen_result.value()->Release();
    ASSERT_TRUE(release_result.has_value());
}

// ============================================================================
// GetRawKeyBytes tests (instance method on OpenSslKeyHandler)
// ============================================================================

TEST_F(OpenSslKeyHandlerTest, GetRawKeyBytes_ReleasedHandler_ReturnsNull)
{
    km::KeyGenerationRequest req{};
    req.algorithm = "HMAC-SHA256";
    req.permissions = score::mw::crypto::KeyOperationPermission::kMac;

    auto gen_result = m_factory->GenerateKey(req);
    ASSERT_TRUE(gen_result.has_value());

    ASSERT_EQ(gen_result.value()->GetProviderId(), 0);  // OPENSSL provider ID
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast)
    const auto* openssl_handler =
        static_cast<const score::crypto::daemon::provider::openssl::OpenSslKeyHandler*>(gen_result.value().get());

    // Should be valid before release
    std::size_t out_size = 0;
    auto* ptr = openssl_handler->GetRawKeyBytes(out_size);
    EXPECT_NE(ptr, nullptr);
    EXPECT_EQ(out_size, 32U);

    // Release and verify it returns null
    static_cast<void>(gen_result.value()->Release());
    out_size = 42;
    ptr = openssl_handler->GetRawKeyBytes(out_size);
    EXPECT_EQ(ptr, nullptr);
    EXPECT_EQ(out_size, 0U);
}

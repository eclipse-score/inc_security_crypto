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

#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_key_handler.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/api/types/key.hpp"
#include "score/crypto/src/daemon/common/algorithm_info.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/i_key_factory.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_ec_key_pair.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_key_factory.hpp"

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
    req.permissions = score::crypto::KeyOperationPermission::kMac;

    auto result = m_factory->GenerateKey(req);

    ASSERT_TRUE(result.has_value());
    auto& handler = result.value();
    auto& handle = handler->GetHandle();
    EXPECT_NE(handle.opaque_id, 0U);
    EXPECT_EQ(handle.key_size, 32U);
    EXPECT_EQ(handle.algorithm, "HMAC-SHA256");
    EXPECT_FALSE(handle.is_asymmetric);
    EXPECT_FALSE(score::crypto::HasPermission(handle.permissions, score::crypto::KeyOperationPermission::kExport));

    // Cleanup
    auto release = handler->Release();
    EXPECT_TRUE(release.has_value());
}

TEST_F(OpenSslKeyHandlerTest, GenerateKey_HmacSha512_Returns64ByteKey)
{
    km::KeyGenerationRequest req{};
    req.algorithm = "HMAC-SHA512";
    req.permissions = score::crypto::KeyOperationPermission::kMac | score::crypto::KeyOperationPermission::kExport;

    auto result = m_factory->GenerateKey(req);

    ASSERT_TRUE(result.has_value());
    auto& handler = result.value();
    EXPECT_EQ(handler->GetHandle().key_size, 64U);
    EXPECT_TRUE(
        score::crypto::HasPermission(handler->GetHandle().permissions, score::crypto::KeyOperationPermission::kExport));

    auto release = handler->Release();
    EXPECT_TRUE(release.has_value());
}

TEST_F(OpenSslKeyHandlerTest, GenerateKey_Aes256_Returns32ByteKey)
{
    km::KeyGenerationRequest req{};
    req.algorithm = "AES-256-CBC";
    req.permissions = score::crypto::KeyOperationPermission::kEncrypt;

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
    req.permissions = score::crypto::KeyOperationPermission::kMac;

    auto result = m_factory->GenerateKey(req);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm);
}

TEST_F(OpenSslKeyHandlerTest, GenerateKey_SymmetricFamilyWithoutKeySize_ReturnsInvalidArgument)
{
    // "AES-256" belongs to the symmetric family but names no mode, so the key
    // size table has no entry for it.
    km::KeyGenerationRequest req{};
    req.algorithm = "AES-256";
    req.permissions = score::crypto::KeyOperationPermission::kEncrypt;

    auto result = m_factory->GenerateKey(req);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
}

// ============================================================================
// EC key pair generation tests
// ============================================================================

class OpenSslEcKeyGenerationTest : public OpenSslKeyHandlerTest, public ::testing::WithParamInterface<const char*>
{
};

TEST_P(OpenSslEcKeyGenerationTest, GenerateKey_EcdsaCurve_ProducesKeyPair)
{
    const auto curve = common::LookupEcCurveOfAlgorithm(GetParam());
    ASSERT_TRUE(curve.has_value());

    km::KeyGenerationRequest req{};
    req.algorithm = GetParam();
    req.permissions = score::crypto::KeyOperationPermission::kSign;
    req.public_key_permissions = score::crypto::KeyOperationPermission::kVerify;

    auto result = m_factory->GenerateKey(req);

    ASSERT_TRUE(result.has_value());
    const auto& handle = result.value()->GetHandle();
    EXPECT_TRUE(handle.is_asymmetric);
    EXPECT_EQ(handle.key_size, curve->field_size);
    EXPECT_NE(handle.opaque_id, 0U);
    EXPECT_EQ(handle.permissions, score::crypto::KeyOperationPermission::kSign);
    ASSERT_TRUE(handle.public_key_permissions.has_value());
    EXPECT_EQ(handle.public_key_permissions.value(), score::crypto::KeyOperationPermission::kVerify);

    EXPECT_TRUE(result.value()->Release().has_value());
}

INSTANTIATE_TEST_SUITE_P(AllCurves,
                         OpenSslEcKeyGenerationTest,
                         ::testing::Values("ECDSA-P256", "ECDSA-P384", "ECDSA-P521"));

TEST_F(OpenSslKeyHandlerTest, GenerateKey_EcdsaWithoutPublicKeyPermissions_LeavesPublicHalfUnrestricted)
{
    km::KeyGenerationRequest req{};
    req.algorithm = "ECDSA-P256";
    req.permissions = score::crypto::KeyOperationPermission::kSign;

    auto result = m_factory->GenerateKey(req);

    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result.value()->GetHandle().public_key_permissions.has_value());

    EXPECT_TRUE(result.value()->Release().has_value());
}

TEST_F(OpenSslKeyHandlerTest, GenerateEcKeyPair_UnsupportedCurve_ReturnsUnsupportedAlgorithm)
{
    // The factory never routes an unknown curve here, so the guard is only
    // reachable by calling the family function directly.
    km::KeyGenerationRequest req{};
    req.algorithm = "ECDSA-P192";

    auto result = score::crypto::daemon::provider::openssl::GenerateEcKeyPair(0, req);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm);
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
    req.permissions = score::crypto::KeyOperationPermission::kMac;

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
    req.permissions = score::crypto::KeyOperationPermission::kMac;

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
    req.permissions = score::crypto::KeyOperationPermission::kMac;

    auto result = m_factory->ImportKey(req);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
}

TEST_F(OpenSslKeyHandlerTest, ImportKey_UnknownAlgorithm_ReturnsUnsupportedAlgorithm)
{
    const std::uint8_t raw_key[32] = {};
    km::KeyImportRequest req{};
    req.key_data = raw_key;
    req.key_data_size = sizeof(raw_key);
    req.algorithm = "RSA-2048";
    req.permissions = score::crypto::KeyOperationPermission::kSign;

    auto result = m_factory->ImportKey(req);

    ASSERT_FALSE(result.has_value()) << "An unclaimed algorithm must not be stored as raw symmetric bytes";
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm);
}

TEST_F(OpenSslKeyHandlerTest, ImportKey_SymmetricFamilyWithoutMode_Succeeds)
{
    // Slot configurations name AES keys without a mode ("AES-256").
    const std::uint8_t raw_key[32] = {};
    km::KeyImportRequest req{};
    req.key_data = raw_key;
    req.key_data_size = sizeof(raw_key);
    req.algorithm = "AES-256";
    req.permissions = score::crypto::KeyOperationPermission::kEncrypt;

    auto result = m_factory->ImportKey(req);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value()->GetHandle().key_size, sizeof(raw_key));
    EXPECT_TRUE(result.value()->Release().has_value());
}

// ============================================================================
// EC import tests
// ============================================================================

namespace
{
/// A P-256 public key as a SubjectPublicKeyInfo DER blob — the form a verify-only
/// slot deploys when it holds no private half.
constexpr std::uint8_t kP256SpkiDer[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xc6, 0x6b, 0xdc, 0x53, 0xd6, 0xea, 0xc4, 0xe5, 0x2e, 0xce, 0xb1,
    0xd5, 0x7d, 0x6d, 0x5d, 0x93, 0x91, 0xfc, 0x36, 0xac, 0x1e, 0xf3, 0xc3, 0x25, 0xc6, 0x89, 0x9f, 0x81, 0xb9, 0x11,
    0xff, 0x3f, 0x02, 0x44, 0xf1, 0x37, 0x84, 0x52, 0x03, 0x0f, 0x28, 0x62, 0x0a, 0x4a, 0xd7, 0xbb, 0x13, 0x0f, 0x7c,
    0xbe, 0x39, 0x23, 0x32, 0x6a, 0x61, 0xc9, 0x96, 0x5b, 0xc6, 0x34, 0x39, 0x98, 0xc6, 0x53};

/// A P-256 key pair as an unencrypted PKCS#8 PrivateKeyInfo DER blob — the form a
/// signing slot deploys.
constexpr std::uint8_t kP256Pkcs8Der[] = {
    0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
    0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02, 0x01, 0x01, 0x04, 0x20,
    0x66, 0x1e, 0x6b, 0x7d, 0x30, 0x12, 0xd4, 0x60, 0xe2, 0x5f, 0x5d, 0xa1, 0x64, 0x9f, 0x4c, 0x01, 0xe3, 0xa1,
    0x5c, 0x39, 0xe0, 0xf0, 0x7e, 0x3e, 0x5d, 0xd7, 0xad, 0xd4, 0xd7, 0x67, 0xf2, 0xf9, 0xa1, 0x44, 0x03, 0x42,
    0x00, 0x04, 0x90, 0x41, 0x6f, 0xd3, 0xed, 0x1c, 0xcf, 0x10, 0x0e, 0x20, 0x01, 0x78, 0xf7, 0xa5, 0xe4, 0x1c,
    0x68, 0x53, 0x2e, 0x51, 0xe1, 0x73, 0xd5, 0x1c, 0x09, 0x96, 0x1c, 0x9f, 0x19, 0x75, 0x6a, 0xf7, 0x3d, 0x72,
    0x9a, 0x28, 0xc9, 0x12, 0x6e, 0xf7, 0xbb, 0xab, 0x5f, 0xe9, 0x1f, 0x12, 0x7e, 0x4a, 0xed, 0xc4, 0x46, 0xee,
    0xec, 0x08, 0x82, 0x81, 0xa1, 0x90, 0xa6, 0x27, 0x21, 0x0a, 0x8f, 0xa1};

/// An Ed25519 public key as a SubjectPublicKeyInfo DER blob: valid DER, but not an EC key.
constexpr std::uint8_t kEd25519SpkiDer[] = {0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21,
                                            0x00, 0x4b, 0x8a, 0x1b, 0x83, 0x04, 0xb2, 0xf2, 0x76, 0xb2, 0x74,
                                            0xb6, 0xc4, 0x54, 0xe4, 0x41, 0xcd, 0xf8, 0x93, 0x53, 0xe7, 0x7b,
                                            0xb1, 0xc5, 0x8c, 0x0c, 0xcc, 0xe9, 0x41, 0x2c, 0xa2, 0x6b, 0x68};
}  // namespace

TEST_F(OpenSslKeyHandlerTest, ImportKey_Pkcs8EcKey_KeepsPrivateHalfPermissions)
{
    km::KeyImportRequest req{};
    req.key_data = kP256Pkcs8Der;
    req.key_data_size = sizeof(kP256Pkcs8Der);
    req.algorithm = "ECDSA-P256";
    req.format = score::crypto::FormatType::kDer;
    req.permissions = score::crypto::KeyOperationPermission::kSign | score::crypto::KeyOperationPermission::kVerify;

    auto result = m_factory->ImportKey(req);

    ASSERT_TRUE(result.has_value());
    const auto& handle = result.value()->GetHandle();
    EXPECT_TRUE(handle.is_asymmetric);
    EXPECT_EQ(handle.permissions, req.permissions) << "A private half was imported, so the slot's grant applies to it";
    ASSERT_TRUE(handle.public_key_permissions.has_value());
    EXPECT_EQ(handle.public_key_permissions.value(), req.permissions);

    EXPECT_TRUE(result.value()->Release().has_value());
}

TEST_F(OpenSslKeyHandlerTest, ImportKey_EcUnparsableDer_ReturnsInvalidFormat)
{
    const std::uint8_t garbage[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    km::KeyImportRequest req{};
    req.key_data = garbage;
    req.key_data_size = sizeof(garbage);
    req.algorithm = "ECDSA-P256";
    req.format = score::crypto::FormatType::kDer;
    req.permissions = score::crypto::KeyOperationPermission::kVerify;

    auto result = m_factory->ImportKey(req);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kInvalidFormat);
}

TEST_F(OpenSslKeyHandlerTest, ImportKey_NonEcDer_ReturnsIncompatibleKeyType)
{
    km::KeyImportRequest req{};
    req.key_data = kEd25519SpkiDer;
    req.key_data_size = sizeof(kEd25519SpkiDer);
    req.algorithm = "ECDSA-P256";
    req.format = score::crypto::FormatType::kDer;
    req.permissions = score::crypto::KeyOperationPermission::kVerify;

    auto result = m_factory->ImportKey(req);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kIncompatibleKeyType);
}

TEST_F(OpenSslKeyHandlerTest, ImportEcKey_UnsupportedCurve_ReturnsUnsupportedAlgorithm)
{
    // The factory never routes an unknown curve here, so the guard is only
    // reachable by calling the family function directly.
    km::KeyImportRequest req{};
    req.key_data = kP256SpkiDer;
    req.key_data_size = sizeof(kP256SpkiDer);
    req.algorithm = "ECDSA-P192";
    req.format = score::crypto::FormatType::kDer;

    auto result = score::crypto::daemon::provider::openssl::ImportEcKey(0, req);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm);
}

TEST_F(OpenSslKeyHandlerTest, ImportKey_PublicOnlyEcKey_DropsPrivateHalfPermissions)
{
    // The grant describes the slot, so a slot allowing kSign can still deploy a
    // blob carrying only the public half. The handle must not then claim kSign:
    // the mediator checks the handle, and a key with no private scalar would
    // pass that check and fail inside OpenSSL instead.
    km::KeyImportRequest req{};
    req.key_data = kP256SpkiDer;
    req.key_data_size = sizeof(kP256SpkiDer);
    req.algorithm = "ECDSA-P256";
    req.format = score::crypto::FormatType::kDer;
    req.permissions = score::crypto::KeyOperationPermission::kSign | score::crypto::KeyOperationPermission::kVerify;

    auto result = m_factory->ImportKey(req);

    ASSERT_TRUE(result.has_value()) << "A public-only EC key is a legitimate import";
    const auto& handle = result.value()->GetHandle();

    EXPECT_TRUE(handle.is_asymmetric);
    EXPECT_FALSE(score::crypto::HasPermission(handle.permissions, score::crypto::KeyOperationPermission::kSign))
        << "No private half was imported, so nothing may sign with this handle";

    ASSERT_TRUE(handle.public_key_permissions.has_value())
        << "An imported key must carry the slot's grant on its public half";
    EXPECT_TRUE(score::crypto::HasPermission(handle.public_key_permissions.value(),
                                             score::crypto::KeyOperationPermission::kVerify))
        << "Verification is exactly what a public-only slot exists for";

    EXPECT_TRUE(result.value()->Release().has_value());
}

TEST_F(OpenSslKeyHandlerTest, ImportKey_EcKeyNonDer_IsRejected)
{
    // The control for the case above: the permission downgrade is reached only
    // after the blob parses, so a rejected format must fail earlier and for a
    // different reason.
    km::KeyImportRequest req{};
    req.key_data = kP256SpkiDer;
    req.key_data_size = sizeof(kP256SpkiDer);
    req.algorithm = "ECDSA-P256";
    req.format = score::crypto::FormatType::kPem;
    req.permissions = score::crypto::KeyOperationPermission::kSign;

    auto result = m_factory->ImportKey(req);

    ASSERT_FALSE(result.has_value()) << "Only DER-encoded EC keys are accepted";
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kInvalidFormat);
}

// ============================================================================
// ReleaseKey tests
// ============================================================================

TEST_F(OpenSslKeyHandlerTest, ReleaseKey_ZeroOpaque_Idempotent)
{
    // Create a handler via GenerateKey and test that Release is idempotent
    km::KeyGenerationRequest req{};
    req.algorithm = "HMAC-SHA256";
    req.permissions = score::crypto::KeyOperationPermission::kMac;

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
    req.permissions = score::crypto::KeyOperationPermission::kMac;

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
    req.permissions = score::crypto::KeyOperationPermission::kMac;

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

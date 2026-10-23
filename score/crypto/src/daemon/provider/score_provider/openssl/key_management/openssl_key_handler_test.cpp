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
#include "score/crypto/src/daemon/key_management/interfaces/i_key_factory.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_key_factory.hpp"

#include <gtest/gtest.h>
#include <cstring>
#include <string_view>
#include <vector>

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

/// Decode a hex string into bytes. Test vectors below are quoted verbatim from
/// their source documents, so keeping them as hex keeps them auditable.
std::vector<std::uint8_t> HexToBytes(std::string_view hex)
{
    const auto nibble = [](char c) -> std::uint8_t {
        if ((c >= '0') && (c <= '9'))
        {
            return static_cast<std::uint8_t>(c - '0');
        }
        if ((c >= 'A') && (c <= 'F'))
        {
            return static_cast<std::uint8_t>(c - 'A' + 10);
        }
        if ((c >= 'a') && (c <= 'f'))
        {
            return static_cast<std::uint8_t>(c - 'a' + 10);
        }
        return 0U;
    };

    std::vector<std::uint8_t> out;
    out.reserve(hex.size() / 2U);
    for (std::size_t i = 0U; (i + 1U) < hex.size(); i += 2U)
    {
        out.push_back(static_cast<std::uint8_t>((nibble(hex[i]) << 4U) | nibble(hex[i + 1U])));
    }
    return out;
}

// RFC 6979 Appendix A.2.6 — the public key U = (Ux, Uy) for curve NIST P-384.
// The raw form this feature imports/exports is the uncompressed SEC1 point
// 0x04 || Ux || Uy (97 bytes).
constexpr std::string_view kP384Ux = "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13";
constexpr std::string_view kP384Uy = "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720";

// RFC 6979 Appendix A.2.5 — the public key U = (Ux, Uy) for curve NIST P-256.
constexpr std::string_view kP256Ux = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
constexpr std::string_view kP256Uy = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";

std::vector<std::uint8_t> RawPoint(std::string_view x_hex, std::string_view y_hex)
{
    std::vector<std::uint8_t> point{0x04};
    const auto x = HexToBytes(x_hex);
    const auto y = HexToBytes(y_hex);
    point.insert(point.end(), x.begin(), x.end());
    point.insert(point.end(), y.begin(), y.end());
    return point;
}
}  // namespace

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
// Raw EC public-key import / export tests
//
// Vectors are the published NIST curve points from RFC 6979 Appendix A.2, so a
// correct round-trip reproduces exactly the documented 0x04||X||Y encoding.
// ============================================================================

TEST_F(OpenSslKeyHandlerTest, ImportRawEcPublicKey_P384_IsVerifyOnly)
{
    const auto point = RawPoint(kP384Ux, kP384Uy);
    ASSERT_EQ(point.size(), 97U) << "An uncompressed P-384 point is 1 + 2*48 bytes";

    km::KeyImportRequest req{};
    req.key_data = point.data();
    req.key_data_size = point.size();
    req.algorithm = "ECDSA-P384-SHA512";
    req.format = score::crypto::FormatType::kRaw;
    req.permissions = score::crypto::KeyOperationPermission::kVerify;

    auto result = m_factory->ImportKey(req);

    ASSERT_TRUE(result.has_value()) << "A valid uncompressed point is a legitimate public-key import";
    const auto& handle = result.value()->GetHandle();

    EXPECT_TRUE(handle.is_asymmetric);
    EXPECT_FALSE(score::crypto::HasPermission(handle.permissions, score::crypto::KeyOperationPermission::kSign))
        << "A raw import carries no private scalar, so nothing may sign with it";
    ASSERT_TRUE(handle.public_key_permissions.has_value());
    EXPECT_TRUE(score::crypto::HasPermission(handle.public_key_permissions.value(),
                                             score::crypto::KeyOperationPermission::kVerify));

    EXPECT_TRUE(result.value()->Release().has_value());
}

TEST_F(OpenSslKeyHandlerTest, ExportRawEcPublicKey_P384_ReproducesTheInputPoint)
{
    const auto point = RawPoint(kP384Ux, kP384Uy);

    km::KeyImportRequest req{};
    req.key_data = point.data();
    req.key_data_size = point.size();
    req.algorithm = "ECDSA-P384-SHA512";
    req.format = score::crypto::FormatType::kRaw;
    req.permissions = score::crypto::KeyOperationPermission::kVerify | score::crypto::KeyOperationPermission::kExport;

    auto imported = m_factory->ImportKey(req);
    ASSERT_TRUE(imported.has_value());
    const auto& handle = imported.value()->GetHandle();

    // The two-call size-then-data contract: the size query must agree with the
    // bytes the export actually produces.
    auto size = m_factory->GetExportKeySize(handle, score::crypto::FormatType::kRaw);
    ASSERT_TRUE(size.has_value());
    EXPECT_EQ(size.value(), point.size());

    auto exported = m_factory->ExportKey(handle, score::crypto::FormatType::kRaw);
    ASSERT_TRUE(exported.has_value());
    EXPECT_EQ(exported.value().bytes, point) << "Export must reproduce the imported 0x04||X||Y point verbatim";

    EXPECT_TRUE(imported.value()->Release().has_value());
}

TEST_F(OpenSslKeyHandlerTest, ExportRawEcPublicKey_P256_ReproducesTheInputPoint)
{
    const auto point = RawPoint(kP256Ux, kP256Uy);
    ASSERT_EQ(point.size(), 65U) << "An uncompressed P-256 point is 1 + 2*32 bytes";

    km::KeyImportRequest req{};
    req.key_data = point.data();
    req.key_data_size = point.size();
    req.algorithm = "ECDSA-P256-SHA256";
    req.format = score::crypto::FormatType::kRaw;
    req.permissions = score::crypto::KeyOperationPermission::kVerify | score::crypto::KeyOperationPermission::kExport;

    auto imported = m_factory->ImportKey(req);
    ASSERT_TRUE(imported.has_value());

    auto exported = m_factory->ExportKey(imported.value()->GetHandle(), score::crypto::FormatType::kRaw);
    ASSERT_TRUE(exported.has_value());
    EXPECT_EQ(exported.value().bytes, point);

    EXPECT_TRUE(imported.value()->Release().has_value());
}

TEST_F(OpenSslKeyHandlerTest, RawEcPublicKey_AllThreeCurves_GenerateExportImportRoundTrip)
{
    // All three NIST prime curves must support the raw form. Generating a fresh
    // key avoids needing a published point for every curve while still proving
    // export and import agree end to end on each.
    struct Curve
    {
        common::AlgorithmId algorithm;
        std::size_t point_size;
    };
    const Curve curves[] = {
        {"ECDSA-P256-SHA256", 65U},
        {"ECDSA-P384-SHA512", 97U},
        {"ECDSA-P521-SHA512", 133U},
    };

    for (const auto& curve : curves)
    {
        km::KeyGenerationRequest gen{};
        gen.algorithm = curve.algorithm;
        gen.permissions = score::crypto::KeyOperationPermission::kSign;
        gen.public_key_permissions =
            score::crypto::KeyOperationPermission::kVerify | score::crypto::KeyOperationPermission::kExport;

        auto generated = m_factory->GenerateKey(gen);
        ASSERT_TRUE(generated.has_value()) << "generate failed for " << std::string{curve.algorithm};

        auto exported = m_factory->ExportKey(generated.value()->GetHandle(), score::crypto::FormatType::kRaw);
        ASSERT_TRUE(exported.has_value()) << "export failed for " << std::string{curve.algorithm};
        ASSERT_EQ(exported.value().bytes.size(), curve.point_size);
        EXPECT_EQ(exported.value().bytes.front(), 0x04) << "export must be an uncompressed point";

        km::KeyImportRequest imp{};
        imp.key_data = exported.value().bytes.data();
        imp.key_data_size = exported.value().bytes.size();
        imp.algorithm = curve.algorithm;
        imp.format = score::crypto::FormatType::kRaw;
        imp.permissions =
            score::crypto::KeyOperationPermission::kVerify | score::crypto::KeyOperationPermission::kExport;

        auto reimported = m_factory->ImportKey(imp);
        ASSERT_TRUE(reimported.has_value()) << "reimport failed for " << std::string{curve.algorithm};

        auto reexported = m_factory->ExportKey(reimported.value()->GetHandle(), score::crypto::FormatType::kRaw);
        ASSERT_TRUE(reexported.has_value());
        EXPECT_EQ(reexported.value().bytes, exported.value().bytes)
            << "raw export/import must round-trip for " << std::string{curve.algorithm};

        EXPECT_TRUE(generated.value()->Release().has_value());
        EXPECT_TRUE(reimported.value()->Release().has_value());
    }
}

TEST_F(OpenSslKeyHandlerTest, ImportRawEcPublicKey_WrongLength_IsRejected)
{
    // A compressed point (0x02/0x03 || X) is 49 bytes for P-384; the length
    // check alone turns it away before any curve arithmetic.
    auto point = RawPoint(kP384Ux, kP384Uy);
    point.resize(49U);
    point[0] = 0x03;

    km::KeyImportRequest req{};
    req.key_data = point.data();
    req.key_data_size = point.size();
    req.algorithm = "ECDSA-P384-SHA512";
    req.format = score::crypto::FormatType::kRaw;
    req.permissions = score::crypto::KeyOperationPermission::kVerify;

    auto result = m_factory->ImportKey(req);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kInvalidFormat);
}

TEST_F(OpenSslKeyHandlerTest, ImportRawEcPublicKey_NonUncompressedLeadByte_IsRejected)
{
    // Correct length but a hybrid lead byte (0x06): a different encoding, so it
    // is rejected rather than silently reinterpreted.
    auto point = RawPoint(kP384Ux, kP384Uy);
    point[0] = 0x06;

    km::KeyImportRequest req{};
    req.key_data = point.data();
    req.key_data_size = point.size();
    req.algorithm = "ECDSA-P384-SHA512";
    req.format = score::crypto::FormatType::kRaw;
    req.permissions = score::crypto::KeyOperationPermission::kVerify;

    auto result = m_factory->ImportKey(req);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kInvalidFormat);
}

TEST_F(OpenSslKeyHandlerTest, ImportRawEcPublicKey_OffCurvePoint_IsRejected)
{
    // Right length and lead byte, but a tampered coordinate no longer lies on
    // the curve — the explicit public-key check must catch the invalid point.
    auto point = RawPoint(kP384Ux, kP384Uy);
    point.back() ^= 0x01U;

    km::KeyImportRequest req{};
    req.key_data = point.data();
    req.key_data_size = point.size();
    req.algorithm = "ECDSA-P384-SHA512";
    req.format = score::crypto::FormatType::kRaw;
    req.permissions = score::crypto::KeyOperationPermission::kVerify;

    auto result = m_factory->ImportKey(req);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kInvalidFormat);
}

TEST_F(OpenSslKeyHandlerTest, ExportRawEcPublicKey_WithoutExportPermission_IsDenied)
{
    const auto point = RawPoint(kP384Ux, kP384Uy);

    km::KeyImportRequest req{};
    req.key_data = point.data();
    req.key_data_size = point.size();
    req.algorithm = "ECDSA-P384-SHA512";
    req.format = score::crypto::FormatType::kRaw;
    req.permissions = score::crypto::KeyOperationPermission::kVerify;  // no kExport

    auto imported = m_factory->ImportKey(req);
    ASSERT_TRUE(imported.has_value());
    const auto& handle = imported.value()->GetHandle();

    auto exported = m_factory->ExportKey(handle, score::crypto::FormatType::kRaw);
    ASSERT_FALSE(exported.has_value()) << "Export of a non-exportable public key must be refused";
    EXPECT_EQ(exported.error(), score::crypto::daemon::common::DaemonErrorCode::kKeyNotExportable);

    auto size = m_factory->GetExportKeySize(handle, score::crypto::FormatType::kRaw);
    ASSERT_FALSE(size.has_value());
    EXPECT_EQ(size.error(), score::crypto::daemon::common::DaemonErrorCode::kKeyNotExportable);

    EXPECT_TRUE(imported.value()->Release().has_value());
}


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

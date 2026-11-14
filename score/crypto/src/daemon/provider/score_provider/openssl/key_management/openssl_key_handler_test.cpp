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
#include "score/crypto/src/daemon/common/algorithm_catalog.hpp"
#include "score/crypto/src/daemon/common/algorithm_info.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/i_key_factory.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/detail/openssl_asymmetric_key.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_ec_key_pair.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_ed25519_key_pair.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_key_factory.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_rsa_key_pair.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_symmetric_key.hpp"
#include "score/tests/utility/test_utility.hpp"

#include <gtest/gtest.h>
#include <cstring>
#include <limits>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace km = score::crypto::daemon::key_management;
namespace common = score::crypto::daemon::common;
namespace openssl = score::crypto::daemon::provider::openssl;

namespace
{
/// Distinct from the default-constructed kInvalidProviderId and from 0, so a
/// handle that dropped or swapped the id fails the comparison.
constexpr common::ProviderId kProviderId{7};

/// Catalog row of @p name; requests reach the factory already resolved.
score::crypto::AlgorithmDescriptor Row(std::string_view name)
{
    const auto row = score::crypto::GetAlgorithmDescriptor(name);
    EXPECT_TRUE(row.has_value()) << "not in the catalog: " << name;
    return row.value_or(score::crypto::AlgorithmDescriptor{});
}

/// Names of the catalog rows @p served accepts.
template <typename Predicate>
std::set<std::string_view> ServedRows(Predicate served)
{
    std::set<std::string_view> names;
    for (const auto& row : score::crypto::kAlgorithmCatalog)
    {
        if (served(row))
        {
            names.insert(row.name);
        }
    }
    return names;
}
}  // namespace

// ============================================================================
// Key family claims
// ============================================================================

TEST(OpenSslKeyFamilyTest, EcFamilyServesEccRowsOnEveryCurve)
{
    const std::set<std::string_view> expected{"ECDSA-P256",
                                              "ECDSA-P384",
                                              "ECDSA-P521",
                                              "ECDSA-P256-SHA224",
                                              "ECDSA-P256-SHA256",
                                              "ECDSA-P256-SHA384",
                                              "ECDSA-P256-SHA512",
                                              "ECDSA-P384-SHA224",
                                              "ECDSA-P384-SHA256",
                                              "ECDSA-P384-SHA384",
                                              "ECDSA-P384-SHA512",
                                              "ECDSA-P521-SHA224",
                                              "ECDSA-P521-SHA256",
                                              "ECDSA-P521-SHA384",
                                              "ECDSA-P521-SHA512"};
    EXPECT_EQ(ServedRows(openssl::IsEcKeySupported), expected);

    auto no_curve = Row("ECDSA-P256");
    no_curve.curve = score::crypto::EccCurve::kNone;
    EXPECT_FALSE(openssl::IsEcKeySupported(no_curve));
}

/// RSA-PSS rows name a signature scheme, so only the bare key rows are claimed.
TEST(OpenSslKeyFamilyTest, RsaFamilyServesRsaKeyRowsOnly)
{
    const std::set<std::string_view> expected{"RSA-2048", "RSA-3072", "RSA-4096"};
    EXPECT_EQ(ServedRows(openssl::IsRsaKeySupported), expected);

    auto rsa_1024 = Row("RSA-2048");
    rsa_1024.key_bits = 1024U;
    EXPECT_FALSE(openssl::IsRsaKeySupported(rsa_1024));
}

TEST(OpenSslKeyFamilyTest, Ed25519FamilyServesEd25519Row)
{
    const std::set<std::string_view> expected{"Ed25519"};
    EXPECT_EQ(ServedRows(openssl::IsEd25519KeySupported), expected);
}

TEST(OpenSslKeyFamilyTest, SymmetricFamilyServesAesAndSecretRows)
{
    const std::set<std::string_view> expected{"HMAC-SHA256",
                                              "HMAC-SHA384",
                                              "HMAC-SHA512",
                                              "AES-128-CMAC",
                                              "AES-256-CMAC",
                                              "AES-128-CBC",
                                              "AES-192-CBC",
                                              "AES-256-CBC",
                                              "AES-128-GCM",
                                              "AES-192-GCM",
                                              "AES-256-GCM",
                                              "AES-128",
                                              "AES-192",
                                              "AES-256"};
    EXPECT_EQ(ServedRows(openssl::IsSymmetricKeySupported), expected);
}

/// The factory asks the families in turn, so a row two families claimed would reach only the first.
TEST(OpenSslKeyFamilyTest, NoRowIsClaimedByTwoFamilies)
{
    for (const auto& row : score::crypto::kAlgorithmCatalog)
    {
        const int claims = static_cast<int>(openssl::IsEcKeySupported(row)) +
                           static_cast<int>(openssl::IsRsaKeySupported(row)) +
                           static_cast<int>(openssl::IsEd25519KeySupported(row)) +
                           static_cast<int>(openssl::IsSymmetricKeySupported(row));
        EXPECT_LE(claims, 1) << row.name;
    }
}

class OpenSslKeyHandlerTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        m_factory = std::make_shared<score::crypto::daemon::provider::openssl::OpenSslKeyFactory>(kProviderId);
    }

    std::shared_ptr<score::crypto::daemon::provider::openssl::OpenSslKeyFactory> m_factory;
};

// ============================================================================
// GenerateKey tests
// ============================================================================

TEST_F(OpenSslKeyHandlerTest, GenerateKey_HmacSha256_Returns32ByteKey)
{
    km::KeyGenerationRequest req{};
    req.algorithm = Row("HMAC-SHA256");
    req.permissions = score::crypto::KeyOperationPermission::kMac;

    auto result = m_factory->GenerateKey(req);

    ASSERT_TRUE(result.has_value());
    auto& handler = result.value();
    auto& handle = handler->GetHandle();
    EXPECT_NE(handle.opaque_id, 0U);
    EXPECT_EQ(handle.key_size, 32U);
    EXPECT_EQ(handle.algorithm.name, "HMAC-SHA256");
    EXPECT_FALSE(handle.is_asymmetric);
    EXPECT_FALSE(score::crypto::HasPermission(handle.permissions, score::crypto::KeyOperationPermission::kExport));

    // Cleanup
    auto release = handler->Release();
    EXPECT_TRUE(release.has_value());
}

TEST_F(OpenSslKeyHandlerTest, GenerateKey_HmacSha512_Returns64ByteKey)
{
    km::KeyGenerationRequest req{};
    req.algorithm = Row("HMAC-SHA512");
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
    req.algorithm = Row("AES-256-CBC");
    req.permissions = score::crypto::KeyOperationPermission::kEncrypt;

    auto result = m_factory->GenerateKey(req);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value()->GetHandle().key_size, 32U);

    auto release = result.value()->Release();
    EXPECT_TRUE(release.has_value());
}

TEST_F(OpenSslKeyHandlerTest, GenerateKey_RowWithoutKey_ReturnsUnsupportedAlgorithm)
{
    km::KeyGenerationRequest req{};
    req.algorithm = Row("SHA256");
    req.permissions = score::crypto::KeyOperationPermission::kMac;

    auto result = m_factory->GenerateKey(req);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm);
}

TEST_F(OpenSslKeyHandlerTest, GenerateKey_AesKeyRow_Returns32ByteKey)
{
    // Slot configurations name AES keys without a mode ("AES-256").
    km::KeyGenerationRequest req{};
    req.algorithm = Row("AES-256");
    req.permissions = score::crypto::KeyOperationPermission::kEncrypt;

    auto result = m_factory->GenerateKey(req);

    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result.value()->GetHandle().is_asymmetric);
    EXPECT_EQ(result.value()->GetHandle().key_size, 32U);
    EXPECT_TRUE(result.value()->Release().has_value());
}

TEST_F(OpenSslKeyHandlerTest, GenerateKey_RsaSignatureRow_ReturnsUnsupportedAlgorithm)
{
    // An RSA-PSS row names a signature scheme, not a key to create.
    km::KeyGenerationRequest req{};
    req.algorithm = Row("RSA-PSS-2048-SHA256");
    req.permissions = score::crypto::KeyOperationPermission::kSign;

    auto result = m_factory->GenerateKey(req);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm);
}

TEST_F(OpenSslKeyHandlerTest, GenerateKey_EcdsaSignatureRow_ProducesKeyPairOnItsCurve)
{
    km::KeyGenerationRequest req{};
    req.algorithm = Row("ECDSA-P384-SHA256");
    req.permissions = score::crypto::KeyOperationPermission::kSign;

    auto result = m_factory->GenerateKey(req);

    ASSERT_TRUE(result.has_value());
    const auto& handle = result.value()->GetHandle();
    EXPECT_TRUE(handle.is_asymmetric);
    EXPECT_EQ(handle.key_size, 48U);
    EXPECT_EQ(handle.permissions, score::crypto::KeyOperationPermission::kSign);

    EXPECT_TRUE(result.value()->Release().has_value());
}

TEST_F(OpenSslKeyHandlerTest, GenerateSymmetricKey_ZeroKeyBits_ReturnsInvalidArgument)
{
    // Every catalog symmetric row has a non-zero key size, so the guard needs a row with it cleared.
    km::KeyGenerationRequest req{};
    req.algorithm = Row("AES-256");
    req.algorithm.key_bits = 0U;

    auto result = openssl::GenerateSymmetricKey(kProviderId, req);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
}

TEST_F(OpenSslKeyHandlerTest, GenerateRsaKeyPair_UnsupportedModulus_ReturnsUnsupportedAlgorithm)
{
    km::KeyGenerationRequest req{};
    req.algorithm = Row("RSA-2048");
    req.algorithm.key_bits = 1024U;

    auto result = openssl::GenerateRsaKeyPair(kProviderId, req);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm);
}

TEST_F(OpenSslKeyHandlerTest, GenerateAsymmetricKey_ConfigureFails_ReturnsKeyGenerationFailed)
{
    km::KeyGenerationRequest req{};
    req.algorithm = Row("Ed25519");
    const openssl::detail::KeygenSpec spec{"ED25519", common::kEd25519KeySize, "test"};

    auto result = openssl::detail::GenerateAsymmetricKey(kProviderId, req, spec, [](EVP_PKEY_CTX*) {
        return false;
    });

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kKeyGenerationFailed);
}

TEST_F(OpenSslKeyHandlerTest, GenerateAsymmetricKey_UnknownKeyType_ReturnsAllocationFailed)
{
    km::KeyGenerationRequest req{};
    req.algorithm = Row("Ed25519");
    const openssl::detail::KeygenSpec spec{"NOPE", 0U, "test"};

    auto result = openssl::detail::GenerateAsymmetricKey(kProviderId, req, spec);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kAllocationFailed);
}

// ============================================================================
// EC key pair generation tests
// ============================================================================

class OpenSslEcKeyGenerationTest : public OpenSslKeyHandlerTest, public ::testing::WithParamInterface<const char*>
{
};

TEST_P(OpenSslEcKeyGenerationTest, GenerateKey_EcdsaCurve_ProducesKeyPair)
{
    km::KeyGenerationRequest req{};
    req.algorithm = Row(GetParam());
    req.permissions = score::crypto::KeyOperationPermission::kSign;
    req.public_key_permissions = score::crypto::KeyOperationPermission::kVerify;

    auto result = m_factory->GenerateKey(req);

    ASSERT_TRUE(result.has_value());
    const auto& handle = result.value()->GetHandle();
    EXPECT_TRUE(handle.is_asymmetric);
    EXPECT_EQ(handle.key_size, common::EcFieldSize(req.algorithm));
    EXPECT_NE(handle.opaque_id, 0U);
    EXPECT_EQ(result.value()->GetProviderId(), kProviderId);
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
    req.algorithm = Row("ECDSA-P256");
    req.permissions = score::crypto::KeyOperationPermission::kSign;

    auto result = m_factory->GenerateKey(req);

    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result.value()->GetHandle().public_key_permissions.has_value());

    EXPECT_TRUE(result.value()->Release().has_value());
}

TEST_F(OpenSslKeyHandlerTest, GenerateEcKeyPair_UnsupportedCurve_ReturnsUnsupportedAlgorithm)
{
    // Every catalog ECC row names a supported curve, so the guard needs a row
    // with its curve cleared.
    km::KeyGenerationRequest req{};
    req.algorithm = Row("ECDSA-P256");
    req.algorithm.curve = score::crypto::EccCurve::kNone;

    auto result = openssl::GenerateEcKeyPair(kProviderId, req);

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
    req.algorithm = Row("HMAC-SHA256");
    req.permissions = score::crypto::KeyOperationPermission::kMac;

    auto result = m_factory->ImportKey(req);

    ASSERT_TRUE(result.has_value());
    auto& handler = result.value();
    EXPECT_NE(handler->GetHandle().opaque_id, 0U);
    EXPECT_EQ(handler->GetHandle().key_size, 32U);

    // Verify key comes from the correct provider
    ASSERT_EQ(handler->GetProviderId(), kProviderId);
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
    req.algorithm = Row("HMAC-SHA256");
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
    req.algorithm = Row("HMAC-SHA256");
    req.permissions = score::crypto::KeyOperationPermission::kMac;

    auto result = m_factory->ImportKey(req);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
}

TEST_F(OpenSslKeyHandlerTest, ImportKey_RowWithoutKey_ReturnsUnsupportedAlgorithm)
{
    const std::uint8_t raw_key[32] = {};
    km::KeyImportRequest req{};
    req.key_data = raw_key;
    req.key_data_size = sizeof(raw_key);
    req.algorithm = Row("SHA256");
    req.permissions = score::crypto::KeyOperationPermission::kSign;

    auto result = m_factory->ImportKey(req);

    ASSERT_FALSE(result.has_value()) << "A row of no key family must not be stored as raw symmetric bytes";
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm);
}

TEST_F(OpenSslKeyHandlerTest, ImportKey_SymmetricFamilyWithoutMode_Succeeds)
{
    // Slot configurations name AES keys without a mode ("AES-256").
    const std::uint8_t raw_key[32] = {};
    km::KeyImportRequest req{};
    req.key_data = raw_key;
    req.key_data_size = sizeof(raw_key);
    req.algorithm = Row("AES-256");
    req.permissions = score::crypto::KeyOperationPermission::kEncrypt;

    auto result = m_factory->ImportKey(req);

    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result.value()->GetHandle().is_asymmetric);
    EXPECT_EQ(result.value()->GetHandle().key_size, sizeof(raw_key));

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast)
    const auto* openssl_handler =
        static_cast<const score::crypto::daemon::provider::openssl::OpenSslKeyHandler*>(result.value().get());
    std::size_t out_size = 0U;
    const auto* key_bytes = openssl_handler->GetRawKeyBytes(out_size);
    ASSERT_NE(key_bytes, nullptr);
    ASSERT_EQ(out_size, sizeof(raw_key));
    EXPECT_EQ(std::memcmp(key_bytes, raw_key, sizeof(raw_key)), 0);

    EXPECT_TRUE(result.value()->Release().has_value());
}

// ============================================================================
// EC import tests
// ============================================================================

namespace
{
/// Root of the packaged ECDSA test vectors, supplied to this test through its
/// Bazel @c data dependency and resolved relative to the runfiles root.
constexpr std::string_view kVectorRoot = "score/tests/test_vectors/ecdsa";

/// Reads a packaged test-vector file into a byte vector.
std::vector<std::uint8_t> ReadVector(std::string_view relative_path)
{
    return tests::utility::read_bin(std::string{kVectorRoot} + std::string{relative_path});
}

/// Builds the SEC1 uncompressed point 0x04 || X || Y from a curve's published
/// coordinate vectors.
std::vector<std::uint8_t> ReadRawPoint(std::string_view ux_path, std::string_view uy_path)
{
    const auto x = ReadVector(ux_path);
    const auto y = ReadVector(uy_path);
    std::vector<std::uint8_t> point{0x04};
    point.insert(point.end(), x.begin(), x.end());
    point.insert(point.end(), y.begin(), y.end());
    return point;
}

// NIST public points U = (Ux, Uy) from RFC 6979 Appendix A.2, stored as raw
// big-endian coordinate vectors. The uncompressed form this feature imports and
// exports is 0x04 || Ux || Uy (65 bytes for P-256, 97 for P-384).
std::vector<std::uint8_t> ReadP256RawPoint()
{
    return ReadRawPoint("/P256/p256_ux.bin", "/P256/p256_uy.bin");
}

std::vector<std::uint8_t> ReadP384RawPoint()
{
    return ReadRawPoint("/P384/p384_ux.bin", "/P384/p384_uy.bin");
}

/// A P-256 public key as a SubjectPublicKeyInfo DER blob — the form a verify-only
/// slot deploys when it holds no private half.
std::vector<std::uint8_t> ReadP256SpkiDer()
{
    return ReadVector("/P256-SHA256/siggen_public_key.der");
}

/// A P-384 public key as a SubjectPublicKeyInfo DER blob whose EC point is in
/// *compressed* form (lead byte 0x03, 49-byte point). No published vector ships
/// a compressed point, so this one stays inline: decoding it yields a key whose
/// point-conversion format is compressed, which is exactly the condition that
/// used to make ExportKey emit a 49-byte point instead of the 97-byte
/// uncompressed point GetExportKeySize promises. Generated with:
///   openssl ecparam -name secp384r1 -genkey -noout | \
///   openssl ec -pubout -conv_form compressed -outform DER
constexpr std::uint8_t kP384CompressedSpkiDer[] = {
    0x30, 0x46, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04,
    0x00, 0x22, 0x03, 0x32, 0x00, 0x03, 0xf6, 0x8d, 0x07, 0x37, 0xb9, 0x3e, 0x0f, 0x47, 0xfc, 0xf7, 0xe3, 0xce,
    0x01, 0x37, 0x7b, 0x5f, 0xb0, 0x4c, 0x89, 0x96, 0xee, 0xa9, 0x4a, 0xb1, 0x05, 0x1b, 0x0c, 0xa7, 0x0e, 0xe5,
    0x26, 0x5c, 0x24, 0x59, 0x51, 0x18, 0x34, 0xd1, 0x6c, 0x03, 0xd9, 0x69, 0xb0, 0xcd, 0x0a, 0x76, 0x80, 0x45};

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

/// An RSA-2048 public key as a SubjectPublicKeyInfo DER blob.
constexpr std::uint8_t kRsa2048SpkiDer[] = {
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xcc, 0x4d, 0x5a, 0x2f, 0x94,
    0x5c, 0x81, 0x2a, 0xac, 0xd7, 0x21, 0x7a, 0x3c, 0x58, 0x3a, 0x63, 0x48, 0xab, 0x40, 0x2a, 0x74, 0x78, 0xeb, 0x50,
    0xd6, 0xfd, 0x88, 0x6f, 0xae, 0x8e, 0x5f, 0x1e, 0x2f, 0x25, 0x65, 0x99, 0x8d, 0xd0, 0x85, 0x0e, 0x03, 0x6a, 0xe8,
    0xb2, 0xaa, 0x95, 0x25, 0x2f, 0xfc, 0x66, 0x5c, 0xda, 0x54, 0x13, 0x7a, 0x64, 0x2a, 0x64, 0xdf, 0xb5, 0x6d, 0x23,
    0xb2, 0x22, 0xf0, 0x6e, 0x1a, 0xf4, 0x77, 0x82, 0xa5, 0x0c, 0x22, 0xa8, 0xa3, 0xc7, 0x40, 0x68, 0xae, 0x42, 0xe6,
    0x60, 0x28, 0x18, 0xaf, 0x5f, 0xd1, 0x1a, 0x33, 0x05, 0x42, 0x55, 0xbc, 0xa8, 0x51, 0xa5, 0xc5, 0xd5, 0x8a, 0xe4,
    0x07, 0xaa, 0x99, 0x51, 0xcb, 0x86, 0xaf, 0xa7, 0x85, 0xfc, 0x53, 0xd8, 0x97, 0x0b, 0xaa, 0xb3, 0xe4, 0xb9, 0x64,
    0x85, 0x51, 0xcc, 0xb9, 0xa0, 0x69, 0x3d, 0xaa, 0x0b, 0x6a, 0x92, 0xfb, 0x92, 0x40, 0x8a, 0x89, 0xe1, 0xe7, 0xc4,
    0x64, 0xb2, 0x76, 0x33, 0xf7, 0x83, 0x7c, 0xb2, 0x92, 0x80, 0x37, 0x34, 0x6d, 0x25, 0xb5, 0x8f, 0x1c, 0x4b, 0x04,
    0x2b, 0xcd, 0x64, 0x18, 0x72, 0x46, 0xe1, 0x61, 0x13, 0x31, 0x35, 0x9d, 0x35, 0x5e, 0x97, 0xe0, 0xe5, 0xa5, 0x84,
    0xc2, 0x18, 0xb0, 0x1e, 0x3e, 0x47, 0x76, 0x68, 0xf4, 0x49, 0xe5, 0x83, 0x6c, 0xd9, 0xb6, 0x00, 0x80, 0x0e, 0xa9,
    0x61, 0x21, 0x3c, 0x3f, 0xec, 0x02, 0xee, 0x45, 0x54, 0xc0, 0x3a, 0x75, 0x54, 0xa0, 0x11, 0x25, 0xb9, 0x43, 0x58,
    0xd3, 0xea, 0x95, 0x2b, 0xd0, 0xd9, 0xd5, 0xc9, 0x9c, 0x6c, 0x1d, 0xae, 0x69, 0x9c, 0x5c, 0xeb, 0xf7, 0x3a, 0x92,
    0x5f, 0xf8, 0xde, 0x6b, 0xd5, 0x1d, 0x4d, 0xd4, 0x19, 0x4f, 0x85, 0x14, 0x64, 0x47, 0x1a, 0xb6, 0xac, 0x5f, 0x58,
    0x98, 0x71, 0x5c, 0x7d, 0x02, 0x03, 0x01, 0x00, 0x01};

/// @p der followed by one extra byte, which no complete DER key may carry.
std::vector<std::uint8_t> WithTrailingByte(const std::uint8_t* der, std::size_t size)
{
    std::vector<std::uint8_t> bytes(der, der + size);
    bytes.push_back(0x00U);
    return bytes;
}
}  // namespace

TEST_F(OpenSslKeyHandlerTest, ImportKey_Pkcs8EcKey_KeepsPrivateHalfPermissions)
{
    km::KeyImportRequest req{};
    req.key_data = kP256Pkcs8Der;
    req.key_data_size = sizeof(kP256Pkcs8Der);
    req.algorithm = Row("ECDSA-P256");
    req.format = score::crypto::FormatType::kDer;
    req.permissions = score::crypto::KeyOperationPermission::kSign | score::crypto::KeyOperationPermission::kVerify;

    auto result = m_factory->ImportKey(req);

    ASSERT_TRUE(result.has_value());
    const auto& handle = result.value()->GetHandle();
    EXPECT_TRUE(handle.is_asymmetric);
    EXPECT_EQ(handle.key_size, common::EcFieldSize(req.algorithm));
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
    req.algorithm = Row("ECDSA-P256");
    req.format = score::crypto::FormatType::kDer;
    req.permissions = score::crypto::KeyOperationPermission::kVerify;

    auto result = m_factory->ImportKey(req);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kInvalidFormat);
}

TEST_F(OpenSslKeyHandlerTest, ImportKey_PublicKeyDerWithTrailingByte_ReturnsInvalidFormat)
{
    const auto spki = ReadP256SpkiDer();
    const auto der = WithTrailingByte(spki.data(), spki.size());
    km::KeyImportRequest req{};
    req.key_data = der.data();
    req.key_data_size = der.size();
    req.algorithm = Row("ECDSA-P256");
    req.format = score::crypto::FormatType::kDer;
    req.permissions = score::crypto::KeyOperationPermission::kVerify;

    auto result = m_factory->ImportKey(req);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kInvalidFormat);
}

TEST_F(OpenSslKeyHandlerTest, ImportKey_PrivateKeyDerWithTrailingByte_ReturnsInvalidFormat)
{
    // The private-key parse succeeds on the prefix, so the trailing byte must
    // reject it rather than let the SubjectPublicKeyInfo fallback accept it.
    const auto der = WithTrailingByte(kP256Pkcs8Der, sizeof(kP256Pkcs8Der));
    km::KeyImportRequest req{};
    req.key_data = der.data();
    req.key_data_size = der.size();
    req.algorithm = Row("ECDSA-P256");
    req.format = score::crypto::FormatType::kDer;
    req.permissions = score::crypto::KeyOperationPermission::kSign;

    auto result = m_factory->ImportKey(req);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kInvalidFormat);
}

TEST_F(OpenSslKeyHandlerTest, ImportKey_NonEcDer_ReturnsIncompatibleKeyType)
{
    km::KeyImportRequest req{};
    req.key_data = kEd25519SpkiDer;
    req.key_data_size = sizeof(kEd25519SpkiDer);
    req.algorithm = Row("ECDSA-P256");
    req.format = score::crypto::FormatType::kDer;
    req.permissions = score::crypto::KeyOperationPermission::kVerify;

    auto result = m_factory->ImportKey(req);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kIncompatibleKeyType);
}

TEST_F(OpenSslKeyHandlerTest, ImportEcKey_UnsupportedCurve_ReturnsUnsupportedAlgorithm)
{
    // Every catalog ECC row names a supported curve, so the guard needs a row
    // with its curve cleared.
    const auto spki = ReadP256SpkiDer();
    km::KeyImportRequest req{};
    req.key_data = spki.data();
    req.key_data_size = spki.size();
    req.algorithm = Row("ECDSA-P256");
    req.algorithm.curve = score::crypto::EccCurve::kNone;
    req.format = score::crypto::FormatType::kDer;

    auto result = openssl::ImportEcKey(kProviderId, req);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm);
}

TEST_F(OpenSslKeyHandlerTest, ImportKey_EcKeyOnOtherCurve_ReturnsIncompatibleKeyType)
{
    km::KeyImportRequest req{};
    req.key_data = kP256Pkcs8Der;
    req.key_data_size = sizeof(kP256Pkcs8Der);
    req.algorithm = Row("ECDSA-P384");
    req.format = score::crypto::FormatType::kDer;
    req.permissions = score::crypto::KeyOperationPermission::kSign;

    auto result = m_factory->ImportKey(req);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kIncompatibleKeyType);
}

TEST_F(OpenSslKeyHandlerTest, ImportKey_EcKeyUnderEcdsaSignatureRow_Succeeds)
{
    const auto spki = ReadP256SpkiDer();
    km::KeyImportRequest req{};
    req.key_data = spki.data();
    req.key_data_size = spki.size();
    req.algorithm = Row("ECDSA-P256-SHA256");
    req.format = score::crypto::FormatType::kDer;
    req.permissions = score::crypto::KeyOperationPermission::kVerify;

    auto result = m_factory->ImportKey(req);

    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result.value()->GetHandle().is_asymmetric);
    EXPECT_EQ(result.value()->GetHandle().key_size, 32U);

    EXPECT_TRUE(result.value()->Release().has_value());
}

TEST_F(OpenSslKeyHandlerTest, ImportKey_SizeBeyondLong_ReturnsInvalidArgument)
{
    // The size check runs before the buffer is read, so a one-byte buffer is never overrun.
    const std::uint8_t one_byte = 0x30U;
    km::KeyImportRequest req{};
    req.key_data = &one_byte;
    req.key_data_size = std::numeric_limits<std::size_t>::max();
    req.algorithm = Row("ECDSA-P256");
    req.format = score::crypto::FormatType::kDer;
    req.permissions = score::crypto::KeyOperationPermission::kVerify;

    auto result = m_factory->ImportKey(req);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
}

// ============================================================================
// RSA and Ed25519 key pair tests
// ============================================================================

TEST_F(OpenSslKeyHandlerTest, ImportKey_RsaSignatureRow_ReturnsUnsupportedAlgorithm)
{
    km::KeyImportRequest req{};
    req.key_data = kRsa2048SpkiDer;
    req.key_data_size = sizeof(kRsa2048SpkiDer);
    req.algorithm = Row("RSA-PSS-2048-SHA256");
    req.format = score::crypto::FormatType::kDer;
    req.permissions = score::crypto::KeyOperationPermission::kVerify;

    auto result = m_factory->ImportKey(req);

    ASSERT_FALSE(result.has_value()) << "An RSA-PSS row must not be stored as raw symmetric bytes";
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm);
}

TEST_F(OpenSslKeyHandlerTest, ImportRsaKey_UnsupportedModulus_ReturnsUnsupportedAlgorithm)
{
    km::KeyImportRequest req{};
    req.key_data = kRsa2048SpkiDer;
    req.key_data_size = sizeof(kRsa2048SpkiDer);
    req.algorithm = Row("RSA-2048");
    req.algorithm.key_bits = 1024U;
    req.format = score::crypto::FormatType::kDer;

    auto result = openssl::ImportRsaKey(kProviderId, req);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm);
}

TEST_F(OpenSslKeyHandlerTest, GenerateKey_Rsa2048_ProducesKeyPair)
{
    km::KeyGenerationRequest req{};
    req.algorithm = Row("RSA-2048");
    req.permissions = score::crypto::KeyOperationPermission::kSign;

    auto result = m_factory->GenerateKey(req);

    ASSERT_TRUE(result.has_value());
    const auto& handle = result.value()->GetHandle();
    EXPECT_TRUE(handle.is_asymmetric);
    EXPECT_EQ(handle.key_size, 256U);
    EXPECT_NE(handle.opaque_id, 0U);
    EXPECT_EQ(handle.permissions, score::crypto::KeyOperationPermission::kSign);
    EXPECT_FALSE(handle.public_key_permissions.has_value()) << "An unset public grant stays unrestricted";
    EXPECT_EQ(result.value()->GetProviderId(), kProviderId);

    EXPECT_TRUE(result.value()->Release().has_value());
}

TEST_F(OpenSslKeyHandlerTest, GenerateKey_Ed25519_ProducesKeyPair)
{
    km::KeyGenerationRequest req{};
    req.algorithm = Row("Ed25519");
    req.permissions = score::crypto::KeyOperationPermission::kSign;
    req.public_key_permissions = score::crypto::KeyOperationPermission::kVerify;

    auto result = m_factory->GenerateKey(req);

    ASSERT_TRUE(result.has_value());
    const auto& handle = result.value()->GetHandle();
    EXPECT_TRUE(handle.is_asymmetric);
    EXPECT_EQ(handle.key_size, common::kEd25519KeySize);
    EXPECT_NE(handle.opaque_id, 0U);
    EXPECT_EQ(handle.permissions, score::crypto::KeyOperationPermission::kSign);
    ASSERT_TRUE(handle.public_key_permissions.has_value());
    EXPECT_EQ(handle.public_key_permissions.value(), score::crypto::KeyOperationPermission::kVerify);

    EXPECT_TRUE(result.value()->Release().has_value());
}

TEST_F(OpenSslKeyHandlerTest, ImportKey_PublicOnlyEd25519Key_DropsPrivateHalfPermissions)
{
    km::KeyImportRequest req{};
    req.key_data = kEd25519SpkiDer;
    req.key_data_size = sizeof(kEd25519SpkiDer);
    req.algorithm = Row("Ed25519");
    req.format = score::crypto::FormatType::kDer;
    req.permissions = score::crypto::KeyOperationPermission::kSign | score::crypto::KeyOperationPermission::kVerify;

    auto result = m_factory->ImportKey(req);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value()->GetProviderId(), kProviderId);
    const auto& handle = result.value()->GetHandle();
    EXPECT_TRUE(handle.is_asymmetric);
    EXPECT_EQ(handle.key_size, common::kEd25519KeySize);
    EXPECT_EQ(handle.permissions, score::crypto::KeyOperationPermission::kNone);
    ASSERT_TRUE(handle.public_key_permissions.has_value());
    EXPECT_EQ(handle.public_key_permissions.value(), req.permissions);

    EXPECT_TRUE(result.value()->Release().has_value());
}

TEST_F(OpenSslKeyHandlerTest, ImportKey_NonRsaDerForRsaAlgorithm_ReturnsIncompatibleKeyType)
{
    km::KeyImportRequest req{};
    req.key_data = kEd25519SpkiDer;
    req.key_data_size = sizeof(kEd25519SpkiDer);
    req.algorithm = Row("RSA-2048");
    req.format = score::crypto::FormatType::kDer;
    req.permissions = score::crypto::KeyOperationPermission::kVerify;

    auto result = m_factory->ImportKey(req);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kIncompatibleKeyType);
}

TEST_F(OpenSslKeyHandlerTest, ImportKey_RsaSpki_DropsPrivateHalfPermissions)
{
    km::KeyImportRequest req{};
    req.key_data = kRsa2048SpkiDer;
    req.key_data_size = sizeof(kRsa2048SpkiDer);
    req.algorithm = Row("RSA-2048");
    req.format = score::crypto::FormatType::kDer;
    req.permissions = score::crypto::KeyOperationPermission::kSign | score::crypto::KeyOperationPermission::kVerify;

    auto result = m_factory->ImportKey(req);

    ASSERT_TRUE(result.has_value());
    const auto& handle = result.value()->GetHandle();
    EXPECT_TRUE(handle.is_asymmetric);
    EXPECT_EQ(handle.key_size, 256U);
    EXPECT_EQ(handle.permissions, score::crypto::KeyOperationPermission::kNone);
    ASSERT_TRUE(handle.public_key_permissions.has_value());
    EXPECT_EQ(handle.public_key_permissions.value(), req.permissions);

    EXPECT_TRUE(result.value()->Release().has_value());
}

TEST_F(OpenSslKeyHandlerTest, ImportKey_RsaKeyOfOtherSize_ReturnsIncompatibleKeyType)
{
    km::KeyImportRequest req{};
    req.key_data = kRsa2048SpkiDer;
    req.key_data_size = sizeof(kRsa2048SpkiDer);
    req.algorithm = Row("RSA-3072");
    req.format = score::crypto::FormatType::kDer;
    req.permissions = score::crypto::KeyOperationPermission::kVerify;

    auto result = m_factory->ImportKey(req);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kIncompatibleKeyType);
}

TEST_F(OpenSslKeyHandlerTest, ImportKey_NonEd25519DerForEd25519Algorithm_ReturnsIncompatibleKeyType)
{
    const auto spki = ReadP256SpkiDer();
    km::KeyImportRequest req{};
    req.key_data = spki.data();
    req.key_data_size = spki.size();
    req.algorithm = Row("Ed25519");
    req.format = score::crypto::FormatType::kDer;
    req.permissions = score::crypto::KeyOperationPermission::kVerify;

    auto result = m_factory->ImportKey(req);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kIncompatibleKeyType);
}

TEST_F(OpenSslKeyHandlerTest, ImportKey_PublicOnlyEcKey_DropsPrivateHalfPermissions)
{
    // The grant describes the slot, so a slot allowing kSign can still deploy a
    // blob carrying only the public half. The handle must not then claim kSign:
    // the mediator checks the handle, and a key with no private scalar would
    // pass that check and fail inside OpenSSL instead.
    const auto spki = ReadP256SpkiDer();
    km::KeyImportRequest req{};
    req.key_data = spki.data();
    req.key_data_size = spki.size();
    req.algorithm = Row("ECDSA-P256");
    req.format = score::crypto::FormatType::kDer;
    req.permissions = score::crypto::KeyOperationPermission::kSign | score::crypto::KeyOperationPermission::kVerify;

    auto result = m_factory->ImportKey(req);

    ASSERT_TRUE(result.has_value()) << "A public-only EC key is a legitimate import";
    const auto& handle = result.value()->GetHandle();

    EXPECT_TRUE(handle.is_asymmetric);
    EXPECT_EQ(handle.key_size, common::EcFieldSize(req.algorithm));
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
    const auto spki = ReadP256SpkiDer();
    km::KeyImportRequest req{};
    req.key_data = spki.data();
    req.key_data_size = spki.size();
    req.algorithm = Row("ECDSA-P256");
    req.format = score::crypto::FormatType::kPem;
    req.permissions = score::crypto::KeyOperationPermission::kSign;

    auto result = m_factory->ImportKey(req);

    ASSERT_FALSE(result.has_value()) << "Only DER-encoded EC keys are accepted";
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kInvalidFormat);
}

TEST_F(OpenSslKeyHandlerTest, ImportKey_EcKeyCurveMismatch_IsRejected)
{
    // Regression: the algorithm names the curve the size/export contract is sized
    // against, but the DER blob carries its own curve. A P-384 key smuggled in as
    // ECDSA-P256 must be rejected at import — otherwise GetExportKeySize would
    // report the P-256 size (65 bytes) while ExportKey emits the P-384 point
    // (97 bytes), handing the caller kInsufficientBufferSize at export time.
    km::KeyImportRequest req{};
    req.key_data = kP384CompressedSpkiDer;
    req.key_data_size = sizeof(kP384CompressedSpkiDer);
    req.algorithm = Row("ECDSA-P256");
    req.format = score::crypto::FormatType::kDer;
    req.permissions = score::crypto::KeyOperationPermission::kVerify;

    auto result = m_factory->ImportKey(req);

    ASSERT_FALSE(result.has_value()) << "A P-384 key must not import under a P-256 algorithm";
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kIncompatibleKeyType);
}

// ============================================================================
// Raw EC public-key import / export tests
//
// Vectors are the published NIST curve points from RFC 6979 Appendix A.2, so a
// correct round-trip reproduces exactly the documented 0x04||X||Y encoding.
// ============================================================================

TEST_F(OpenSslKeyHandlerTest, ImportRawEcPublicKey_P384_IsVerifyOnly)
{
    const auto point = ReadP384RawPoint();
    ASSERT_EQ(point.size(), 97U) << "An uncompressed P-384 point is 1 + 2*48 bytes";

    km::KeyImportRequest req{};
    req.key_data = point.data();
    req.key_data_size = point.size();
    req.algorithm = Row("ECDSA-P384-SHA512");
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
    const auto point = ReadP384RawPoint();

    km::KeyImportRequest req{};
    req.key_data = point.data();
    req.key_data_size = point.size();
    req.algorithm = Row("ECDSA-P384-SHA512");
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

TEST_F(OpenSslKeyHandlerTest, ExportRawEcPublicKey_CompressedDerImport_StillExportsUncompressed)
{
    // Regression: OSSL_PKEY_PARAM_PUB_KEY follows the key's point-conversion
    // format. A key decoded from a compressed DER encoding keeps that compressed
    // format, so a naive export would emit a 49-byte P-384 point that both
    // disagrees with GetExportKeySize (97) and is rejected by the raw import
    // path. ExportKey must force uncompressed serialisation so the raw
    // round-trip contract holds.
    km::KeyImportRequest req{};
    req.key_data = kP384CompressedSpkiDer;
    req.key_data_size = sizeof(kP384CompressedSpkiDer);
    req.algorithm = Row("ECDSA-P384-SHA512");
    req.format = score::crypto::FormatType::kDer;
    req.permissions = score::crypto::KeyOperationPermission::kVerify | score::crypto::KeyOperationPermission::kExport;

    auto imported = m_factory->ImportKey(req);
    ASSERT_TRUE(imported.has_value()) << "A compressed-point SPKI is a legitimate public-key import";
    const auto& handle = imported.value()->GetHandle();

    // The size query must agree with the bytes the export actually produces.
    auto size = m_factory->GetExportKeySize(handle, score::crypto::FormatType::kRaw);
    ASSERT_TRUE(size.has_value());
    EXPECT_EQ(size.value(), 97U) << "GetExportKeySize always reports the uncompressed P-384 length";

    auto exported = m_factory->ExportKey(handle, score::crypto::FormatType::kRaw);
    ASSERT_TRUE(exported.has_value());
    ASSERT_EQ(exported.value().bytes.size(), 97U)
        << "Export must be forced to the uncompressed 1 + 2*48 encoding, not the compressed 49";
    EXPECT_EQ(exported.value().bytes.front(), 0x04) << "An uncompressed SEC1 point leads with 0x04";
    EXPECT_EQ(exported.value().bytes.size(), size.value()) << "Export size must match the size query";

    // And the uncompressed export must round-trip back through the raw import.
    km::KeyImportRequest reimp{};
    reimp.key_data = exported.value().bytes.data();
    reimp.key_data_size = exported.value().bytes.size();
    reimp.algorithm = Row("ECDSA-P384-SHA512");
    reimp.format = score::crypto::FormatType::kRaw;
    reimp.permissions = score::crypto::KeyOperationPermission::kVerify | score::crypto::KeyOperationPermission::kExport;

    auto reimported = m_factory->ImportKey(reimp);
    ASSERT_TRUE(reimported.has_value()) << "The forced-uncompressed export must satisfy the raw import contract";

    auto reexported = m_factory->ExportKey(reimported.value()->GetHandle(), score::crypto::FormatType::kRaw);
    ASSERT_TRUE(reexported.has_value());
    EXPECT_EQ(reexported.value().bytes, exported.value().bytes) << "Raw export/import must round-trip";

    EXPECT_TRUE(imported.value()->Release().has_value());
    EXPECT_TRUE(reimported.value()->Release().has_value());
}

TEST_F(OpenSslKeyHandlerTest, ExportRawEcPublicKey_P256_ReproducesTheInputPoint)
{
    const auto point = ReadP256RawPoint();
    ASSERT_EQ(point.size(), 65U) << "An uncompressed P-256 point is 1 + 2*32 bytes";

    km::KeyImportRequest req{};
    req.key_data = point.data();
    req.key_data_size = point.size();
    req.algorithm = Row("ECDSA-P256-SHA256");
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
        std::string_view algorithm;
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
        gen.algorithm = Row(curve.algorithm);
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
        imp.algorithm = Row(curve.algorithm);
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
    auto point = ReadP384RawPoint();
    point.resize(49U);
    point[0] = 0x03;

    km::KeyImportRequest req{};
    req.key_data = point.data();
    req.key_data_size = point.size();
    req.algorithm = Row("ECDSA-P384-SHA512");
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
    auto point = ReadP384RawPoint();
    point[0] = 0x06;

    km::KeyImportRequest req{};
    req.key_data = point.data();
    req.key_data_size = point.size();
    req.algorithm = Row("ECDSA-P384-SHA512");
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
    auto point = ReadP384RawPoint();
    point.back() ^= 0x01U;

    km::KeyImportRequest req{};
    req.key_data = point.data();
    req.key_data_size = point.size();
    req.algorithm = Row("ECDSA-P384-SHA512");
    req.format = score::crypto::FormatType::kRaw;
    req.permissions = score::crypto::KeyOperationPermission::kVerify;

    auto result = m_factory->ImportKey(req);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kInvalidFormat);
}

TEST_F(OpenSslKeyHandlerTest, ExportRawEcPublicKey_WithoutExportPermission_IsDenied)
{
    const auto point = ReadP384RawPoint();

    km::KeyImportRequest req{};
    req.key_data = point.data();
    req.key_data_size = point.size();
    req.algorithm = Row("ECDSA-P384-SHA512");
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
    req.algorithm = Row("HMAC-SHA256");
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
    req.algorithm = Row("HMAC-SHA256");
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
    req.algorithm = Row("HMAC-SHA256");
    req.permissions = score::crypto::KeyOperationPermission::kMac;

    auto gen_result = m_factory->GenerateKey(req);
    ASSERT_TRUE(gen_result.has_value());

    ASSERT_EQ(gen_result.value()->GetProviderId(), kProviderId);
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

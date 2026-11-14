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
#include "score/crypto/src/daemon/key_management/interfaces/i_key_factory.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_slot_config.hpp"
#include "score/crypto/src/daemon/key_management/slot/file_backed_slot_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_key_factory.hpp"
#include "score/tests/utility/test_utility.hpp"

#include <gtest/gtest.h>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace km = score::crypto::daemon::key_management;
namespace common = score::crypto::daemon::common;

namespace
{
/// Catalog row of @p name; requests reach the factory already resolved.
score::crypto::AlgorithmDescriptor Row(std::string_view name)
{
    const auto row = score::crypto::GetAlgorithmDescriptor(name);
    EXPECT_TRUE(row.has_value()) << "not in the catalog: " << name;
    return row.value_or(score::crypto::AlgorithmDescriptor{});
}
}  // namespace

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

TEST_F(OpenSslKeyHandlerTest, GenerateKey_RowWithoutKey_ReturnsError)
{
    km::KeyGenerationRequest req{};
    req.algorithm = Row("SHA256");
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
    req.algorithm = Row("HMAC-SHA256");
    req.format = score::crypto::FormatType::kRaw;
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
}

// ============================================================================
// Symmetric import validation tests
// ============================================================================

namespace
{
/// Builds a request importing @p key under the catalog row @p name.
km::KeyImportRequest SymmetricImport(std::string_view name,
                                     const std::vector<std::uint8_t>& key,
                                     std::optional<score::crypto::FormatType> format = score::crypto::FormatType::kRaw)
{
    km::KeyImportRequest req{};
    req.key_data = key.data();
    req.key_data_size = key.size();
    req.algorithm = Row(name);
    req.format = format;
    req.permissions = score::crypto::KeyOperationPermission::kAll;
    return req;
}
}  // namespace

TEST_F(OpenSslKeyHandlerTest, ImportKey_SymmetricNonRawFormat_IsRejected)
{
    // Symmetric keys have no ASN.1 or PEM encoding; a DER or PEM label on raw
    // bytes is a caller error and must not be silently accepted.
    const std::vector<std::uint8_t> key(32U, 0x5AU);
    for (const auto format : {score::crypto::FormatType::kDer, score::crypto::FormatType::kPem})
    {
        for (const auto* name : {"AES-256", "HMAC-SHA256"})
        {
            auto result = m_factory->ImportKey(SymmetricImport(name, key, format));
            ASSERT_FALSE(result.has_value()) << name << " with format " << static_cast<int>(format);
            EXPECT_EQ(result.error(), common::DaemonErrorCode::kInvalidFormat) << name;
        }
    }
}

TEST_F(OpenSslKeyHandlerTest, ImportKey_AesWrongLength_IsRejected)
{
    struct Case
    {
        const char* name;
        std::size_t size;
    };
    for (const auto& c : {Case{"AES-128", 16U},
                          Case{"AES-192", 24U},
                          Case{"AES-256", 32U},
                          Case{"AES-128-CBC", 16U},
                          Case{"AES-256-GCM", 32U},
                          Case{"AES-256-CMAC", 32U}})
    {
        for (const std::size_t wrong : {c.size - 1U, c.size + 1U, std::size_t{1U}, std::size_t{64U}})
        {
            const std::vector<std::uint8_t> key(wrong, 0x11U);
            auto result = m_factory->ImportKey(SymmetricImport(c.name, key));
            ASSERT_FALSE(result.has_value()) << c.name << " accepted " << wrong << " bytes";
            EXPECT_EQ(result.error(), common::DaemonErrorCode::kIncompatibleKeyType) << c.name << " " << wrong;
        }

        const std::vector<std::uint8_t> key(c.size, 0x11U);
        auto result = m_factory->ImportKey(SymmetricImport(c.name, key));
        ASSERT_TRUE(result.has_value()) << c.name << " rejected its own key length " << c.size;
        EXPECT_EQ(result.value()->GetHandle().key_size, c.size);
        EXPECT_TRUE(result.value()->Release().has_value());
    }
}

TEST_F(OpenSslKeyHandlerTest, ImportKey_HmacShorterThanDigest_IsRejected)
{
    struct Case
    {
        const char* name;
        std::size_t digest_size;
    };
    for (const auto& c : {Case{"HMAC-SHA256", 32U}, Case{"HMAC-SHA384", 48U}, Case{"HMAC-SHA512", 64U}})
    {
        const std::vector<std::uint8_t> short_key(c.digest_size - 1U, 0x22U);
        auto rejected = m_factory->ImportKey(SymmetricImport(c.name, short_key));
        ASSERT_FALSE(rejected.has_value()) << c.name << " accepted a key shorter than its digest";
        EXPECT_EQ(rejected.error(), common::DaemonErrorCode::kIncompatibleKeyType) << c.name;

        // The digest length is a floor, not a fixed size: a longer HMAC key is valid.
        for (const std::size_t good : {c.digest_size, 2U * c.digest_size})
        {
            const std::vector<std::uint8_t> key(good, 0x22U);
            auto accepted = m_factory->ImportKey(SymmetricImport(c.name, key));
            ASSERT_TRUE(accepted.has_value()) << c.name << " rejected " << good << " bytes";
            EXPECT_EQ(accepted.value()->GetHandle().key_size, good);
            EXPECT_TRUE(accepted.value()->Release().has_value());
        }
    }
}

TEST_F(OpenSslKeyHandlerTest, ImportKey_RowWithoutKey_IsRejected)
{
    const std::vector<std::uint8_t> key(32U, 0x33U);
    for (const auto* name : {"SHA256", "RSA-PSS-2048-SHA256"})
    {
        auto result = m_factory->ImportKey(SymmetricImport(name, key));
        ASSERT_FALSE(result.has_value()) << name << " names no symmetric key";
        EXPECT_EQ(result.error(), common::DaemonErrorCode::kInvalidArgument) << name;
    }
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
}  // namespace

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
    EXPECT_FALSE(score::crypto::HasPermission(handle.permissions, score::crypto::KeyOperationPermission::kSign))
        << "No private half was imported, so nothing may sign with this handle";

    ASSERT_TRUE(handle.public_key_permissions.has_value())
        << "An imported key must carry the slot's grant on its public half";
    EXPECT_TRUE(score::crypto::HasPermission(handle.public_key_permissions.value(),
                                             score::crypto::KeyOperationPermission::kVerify))
        << "Verification is exactly what a public-only slot exists for";

    EXPECT_TRUE(result.value()->Release().has_value());
}

TEST_F(OpenSslKeyHandlerTest, ImportKey_EcKeyDerBytesLabelledPem_IsRejected)
{
    // The control for the case above: the permission downgrade is reached only
    // after the blob parses, so DER bytes declared as PEM must fail earlier and
    // for a different reason.
    const auto spki = ReadP256SpkiDer();
    km::KeyImportRequest req{};
    req.key_data = spki.data();
    req.key_data_size = spki.size();
    req.algorithm = Row("ECDSA-P256");
    req.format = score::crypto::FormatType::kPem;
    req.permissions = score::crypto::KeyOperationPermission::kSign;

    auto result = m_factory->ImportKey(req);

    ASSERT_FALSE(result.has_value()) << "Binary DER is not PEM armour";
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
// PEM import tests
//
// The PEM vectors are the packaged NIST DER vectors re-encoded with the openssl
// CLI (see score/tests/test_vectors/ecdsa/P256-SHA256/reference.md).
// ============================================================================

namespace
{
km::KeyImportRequest PemImport(std::string_view algorithm, const std::vector<std::uint8_t>& pem)
{
    km::KeyImportRequest req{};
    req.key_data = pem.data();
    req.key_data_size = pem.size();
    req.algorithm = Row(algorithm);
    req.format = score::crypto::FormatType::kPem;
    req.permissions = score::crypto::KeyOperationPermission::kSign | score::crypto::KeyOperationPermission::kVerify |
                      score::crypto::KeyOperationPermission::kExport;
    return req;
}

std::vector<std::uint8_t> Bytes(std::string_view text)
{
    return std::vector<std::uint8_t>{text.begin(), text.end()};
}
}  // namespace

TEST_F(OpenSslKeyHandlerTest, ImportPem_PrivateKeys_KeepPrivateHalf)
{
    struct Case
    {
        const char* algorithm;
        const char* path;
    };
    for (const auto& c : {Case{"ECDSA-P256", "/P256-SHA256/siggen_private_key.pem"},
                          Case{"ECDSA-P256", "/P256-SHA256/siggen_private_key_sec1.pem"},
                          Case{"ECDSA-P384", "/P384-SHA384/siggen_private_key.pem"}})
    {
        const auto pem = ReadVector(c.path);
        ASSERT_FALSE(pem.empty()) << c.path;

        auto result = m_factory->ImportKey(PemImport(c.algorithm, pem));

        ASSERT_TRUE(result.has_value()) << c.path << " failed with error "
                                        << (result.has_value() ? 0 : static_cast<int>(result.error()));
        const auto& handle = result.value()->GetHandle();
        EXPECT_TRUE(handle.is_asymmetric);
        EXPECT_TRUE(score::crypto::HasPermission(handle.permissions, score::crypto::KeyOperationPermission::kSign))
            << c.path << " carries a private scalar, so the private half keeps its grant";
        EXPECT_TRUE(result.value()->Release().has_value());
    }
}

TEST_F(OpenSslKeyHandlerTest, ImportPem_PublicKey_MatchesDerImport)
{
    const auto pem = ReadVector("/P256-SHA256/siggen_public_key.pem");
    const auto der = ReadP256SpkiDer();

    auto from_pem = m_factory->ImportKey(PemImport("ECDSA-P256", pem));
    ASSERT_TRUE(from_pem.has_value());
    EXPECT_FALSE(score::crypto::HasPermission(from_pem.value()->GetHandle().permissions,
                                              score::crypto::KeyOperationPermission::kSign))
        << "A PUBLIC KEY block carries no private half";

    km::KeyImportRequest der_req = PemImport("ECDSA-P256", der);
    der_req.format = score::crypto::FormatType::kDer;
    auto from_der = m_factory->ImportKey(der_req);
    ASSERT_TRUE(from_der.has_value());

    auto pem_point = m_factory->ExportKey(from_pem.value()->GetHandle(), score::crypto::FormatType::kRaw);
    auto der_point = m_factory->ExportKey(from_der.value()->GetHandle(), score::crypto::FormatType::kRaw);
    ASSERT_TRUE(pem_point.has_value());
    ASSERT_TRUE(der_point.has_value());
    EXPECT_EQ(pem_point.value().bytes.size(), 65U);
    EXPECT_EQ(pem_point.value().bytes, der_point.value().bytes);

    EXPECT_TRUE(from_pem.value()->Release().has_value());
    EXPECT_TRUE(from_der.value()->Release().has_value());
}

TEST_F(OpenSslKeyHandlerTest, ImportPem_WrongCurve_IsRejected)
{
    const auto pem = ReadVector("/P384-SHA384/siggen_private_key.pem");

    auto result = m_factory->ImportKey(PemImport("ECDSA-P256", pem));

    ASSERT_FALSE(result.has_value()) << "A P-384 key must not import under a P-256 algorithm";
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kIncompatibleKeyType);
}

TEST_F(OpenSslKeyHandlerTest, ImportPem_EncryptedKey_IsRejected)
{
    // No passphrase can be supplied through ImportKey, so encrypted PEM is
    // refused instead of prompting on the daemon's terminal.
    for (const auto* path :
         {"/P256-SHA256/siggen_private_key_encrypted.pem", "/P256-SHA256/siggen_private_key_sec1_encrypted.pem"})
    {
        const auto pem = ReadVector(path);
        ASSERT_FALSE(pem.empty()) << path;

        auto result = m_factory->ImportKey(PemImport("ECDSA-P256", pem));

        ASSERT_FALSE(result.has_value()) << path;
        EXPECT_EQ(result.error(), common::DaemonErrorCode::kInvalidFormat) << path;
    }
}

TEST_F(OpenSslKeyHandlerTest, ImportPem_MalformedInput_IsRejected)
{
    const auto pem = ReadVector("/P256-SHA256/siggen_public_key.pem");
    const std::string text{pem.begin(), pem.end()};
    const std::string body_only = text.substr(text.find('\n') + 1U);

    const std::vector<std::pair<const char*, std::vector<std::uint8_t>>> cases = {
        {"not PEM at all", Bytes("garbage")},
        {"leading garbage", Bytes("junk\n" + text)},
        {"trailing garbage", Bytes(text + "junk\n")},
        {"second PEM block", Bytes(text + text)},
        {"missing END line", Bytes(text.substr(0U, text.find("-----END")))},
        {"missing BEGIN line", Bytes(body_only)},
        {"unsupported label",
         Bytes("-----BEGIN CERTIFICATE-----\n" + body_only.substr(0U, body_only.find("-----END")) +
               "-----END CERTIFICATE-----\n")},
        {"corrupt base64", Bytes("-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYI!!!!\n-----END PUBLIC KEY-----\n")},
    };

    for (const auto& [what, data] : cases)
    {
        auto result = m_factory->ImportKey(PemImport("ECDSA-P256", data));
        ASSERT_FALSE(result.has_value()) << what;
        EXPECT_EQ(result.error(), common::DaemonErrorCode::kInvalidFormat) << what;
    }
}

TEST_F(OpenSslKeyHandlerTest, ImportPem_LabelDisagreesWithContent_IsRejected)
{
    // A PRIVATE KEY label around a SubjectPublicKeyInfo body (and the reverse)
    // is not a key this factory can classify reliably, so it is refused.
    const auto pub = ReadVector("/P256-SHA256/siggen_public_key.pem");
    const auto priv = ReadVector("/P256-SHA256/siggen_private_key.pem");
    auto relabel = [](const std::vector<std::uint8_t>& pem, const std::string& from, const std::string& to) {
        std::string text{pem.begin(), pem.end()};
        for (std::size_t pos = text.find(from); pos != std::string::npos; pos = text.find(from, pos + to.size()))
        {
            text.replace(pos, from.size(), to);
        }
        return Bytes(text);
    };

    for (const auto& data : {relabel(pub, "PUBLIC KEY", "PRIVATE KEY"), relabel(priv, "PRIVATE KEY", "PUBLIC KEY")})
    {
        auto result = m_factory->ImportKey(PemImport("ECDSA-P256", data));
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error(), common::DaemonErrorCode::kInvalidFormat);
    }
}

TEST_F(OpenSslKeyHandlerTest, ImportPem_SurroundingWhitespace_IsAccepted)
{
    const auto pem = ReadVector("/P256-SHA256/siggen_public_key.pem");
    const std::string text{pem.begin(), pem.end()};

    auto result = m_factory->ImportKey(PemImport("ECDSA-P256", Bytes("\n  " + text + "\r\n\n")));

    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result.value()->Release().has_value());
}

// ============================================================================
// Native format (no format given) import tests
//
// Without a format, symmetric keys are raw bytes and asymmetric key material is
// detected from the data (PEM, DER, or an EC raw point). Detection only picks
// the parser: the curve, length and encryption checks still apply.
// ============================================================================

namespace
{
km::KeyImportRequest NativeImport(std::string_view algorithm, const std::vector<std::uint8_t>& data)
{
    km::KeyImportRequest req = PemImport(algorithm, data);
    req.format = std::nullopt;
    return req;
}

int ErrorOf(const score::crypto::Expected<km::IKeyHandler::Sptr, common::DaemonErrorCode>& result)
{
    return result.has_value() ? 0 : static_cast<int>(result.error());
}
}  // namespace

TEST_F(OpenSslKeyHandlerTest, ImportNative_Symmetric_IsRawWithLengthChecks)
{
    for (const auto& [name, good_size, bad_size] :
         {std::tuple<const char*, std::size_t, std::size_t>{"AES-128", 16U, 15U},
          std::tuple<const char*, std::size_t, std::size_t>{"AES-256", 32U, 31U},
          std::tuple<const char*, std::size_t, std::size_t>{"HMAC-SHA256", 32U, 31U}})
    {
        const std::vector<std::uint8_t> good(good_size, 0x5AU);
        auto ok = m_factory->ImportKey(SymmetricImport(name, good, std::nullopt));
        ASSERT_TRUE(ok.has_value()) << name << " error " << ErrorOf(ok);
        EXPECT_EQ(ok.value()->GetHandle().key_size, good_size);
        EXPECT_TRUE(ok.value()->Release().has_value());

        const std::vector<std::uint8_t> bad(bad_size, 0x5AU);
        auto rejected = m_factory->ImportKey(SymmetricImport(name, bad, std::nullopt));
        ASSERT_FALSE(rejected.has_value()) << name << " accepted " << bad_size << " bytes";
        EXPECT_EQ(rejected.error(), common::DaemonErrorCode::kIncompatibleKeyType) << name;
    }
}

TEST_F(OpenSslKeyHandlerTest, ImportNative_PrivateDerAndPem_KeepPrivateHalf)
{
    struct Case
    {
        const char* algorithm;
        const char* path;
    };
    for (const auto& c : {Case{"ECDSA-P256", "/P256-SHA256/siggen_private_key.der"},
                          Case{"ECDSA-P256", "/P256-SHA256/siggen_private_key.pem"},
                          Case{"ECDSA-P256", "/P256-SHA256/siggen_private_key_sec1.pem"},
                          Case{"ECDSA-P384", "/P384-SHA384/siggen_private_key.der"},
                          Case{"ECDSA-P384", "/P384-SHA384/siggen_private_key.pem"}})
    {
        const auto data = ReadVector(c.path);
        ASSERT_FALSE(data.empty()) << c.path;

        auto result = m_factory->ImportKey(NativeImport(c.algorithm, data));

        ASSERT_TRUE(result.has_value()) << c.path << " failed with error " << ErrorOf(result);
        EXPECT_TRUE(score::crypto::HasPermission(result.value()->GetHandle().permissions,
                                                 score::crypto::KeyOperationPermission::kSign))
            << c.path;
        EXPECT_TRUE(result.value()->Release().has_value());
    }
}

TEST_F(OpenSslKeyHandlerTest, ImportNative_PublicDerPemAndRawPoint_GiveTheSameKey)
{
    const auto der = ReadP256SpkiDer();
    const auto pem = ReadVector("/P256-SHA256/siggen_public_key.pem");

    auto reference = m_factory->ImportKey(NativeImport("ECDSA-P256", der));
    ASSERT_TRUE(reference.has_value()) << "SPKI DER: error " << ErrorOf(reference);
    auto point = m_factory->ExportKey(reference.value()->GetHandle(), score::crypto::FormatType::kRaw);
    ASSERT_TRUE(point.has_value());
    ASSERT_EQ(point.value().bytes.size(), 65U);
    const std::vector<std::uint8_t> raw_point{point.value().bytes.begin(), point.value().bytes.end()};

    for (const auto* data : {&pem, &raw_point})
    {
        auto result = m_factory->ImportKey(NativeImport("ECDSA-P256", *data));
        ASSERT_TRUE(result.has_value()) << "error " << ErrorOf(result);
        EXPECT_FALSE(score::crypto::HasPermission(result.value()->GetHandle().permissions,
                                                  score::crypto::KeyOperationPermission::kSign))
            << "A public key carries no private half";
        auto exported = m_factory->ExportKey(result.value()->GetHandle(), score::crypto::FormatType::kRaw);
        ASSERT_TRUE(exported.has_value());
        EXPECT_EQ(exported.value().bytes, point.value().bytes);
        EXPECT_TRUE(result.value()->Release().has_value());
    }
    EXPECT_TRUE(reference.value()->Release().has_value());
}

TEST_F(OpenSslKeyHandlerTest, ImportNative_StillChecksTheCurve)
{
    for (const auto& data : {ReadVector("/P384/p384_public_key.pem"),
                             ReadVector("/P384/p384_public_key.der"),
                             ReadVector("/P384-SHA384/siggen_private_key.pem")})
    {
        auto result = m_factory->ImportKey(NativeImport("ECDSA-P256", data));
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error(), common::DaemonErrorCode::kIncompatibleKeyType);
    }
    auto raw = m_factory->ImportKey(NativeImport("ECDSA-P256", ReadP384RawPoint()));
    EXPECT_FALSE(raw.has_value()) << "A 97-byte P-384 point is not a P-256 key";
}

TEST_F(OpenSslKeyHandlerTest, ImportNative_GarbageAndEncryptedPem_AreRejected)
{
    const auto pem = ReadVector("/P256-SHA256/siggen_public_key.pem");
    const std::string pem_text{pem.begin(), pem.end()};
    struct Case
    {
        const char* algorithm;
        std::vector<std::uint8_t> data;
    };
    const std::vector<Case> cases{
        {"ECDSA-P256", Bytes("not a key at all")},
        {"ECDSA-P256", {0x30U, 0x03U, 0x02U, 0x01U, 0x01U}},
        {"ECDSA-P256", Bytes("junk\n" + pem_text)},
        {"ECDSA-P256", Bytes("-----BEGIN PUBLIC KEY-----\n!!!!\n-----END PUBLIC KEY-----\n")},
        {"ECDSA-P256", ReadVector("/P256-SHA256/siggen_private_key_encrypted.pem")},
        {"ECDSA-P256", ReadVector("/P256-SHA256/siggen_private_key_sec1_encrypted.pem")},
        // A leading 0x04 means a raw point only for EC algorithms.
        {"Ed25519", std::vector<std::uint8_t>(33U, 0x04U)},
        {"RSA-2048", std::vector<std::uint8_t>(65U, 0x04U)},
    };
    for (const auto& c : cases)
    {
        auto result = m_factory->ImportKey(NativeImport(c.algorithm, c.data));
        ASSERT_FALSE(result.has_value()) << c.algorithm << " accepted " << c.data.size() << " bytes";
        EXPECT_EQ(result.error(), common::DaemonErrorCode::kInvalidFormat) << c.algorithm;
    }

    auto off_curve = m_factory->ImportKey(NativeImport("ECDSA-P256", std::vector<std::uint8_t>(65U, 0x04U)));
    EXPECT_FALSE(off_curve.has_value()) << "A 0x04-led blob that is not on the curve is no key";
}

TEST_F(OpenSslKeyHandlerTest, ImportExplicitRaw_OnNonEcAsymmetric_IsRejected)
{
    const auto private_der = ReadVector("/P256-SHA256/siggen_private_key.der");
    for (const auto* algorithm : {"Ed25519", "RSA-2048"})
    {
        km::KeyImportRequest req = NativeImport(algorithm, private_der);
        req.format = score::crypto::FormatType::kRaw;
        auto result = m_factory->ImportKey(req);
        ASSERT_FALSE(result.has_value()) << algorithm;
        EXPECT_EQ(result.error(), common::DaemonErrorCode::kInvalidFormat) << algorithm;
    }
    km::KeyImportRequest ec_req = NativeImport("ECDSA-P256", private_der);
    ec_req.format = score::crypto::FormatType::kRaw;
    EXPECT_FALSE(m_factory->ImportKey(ec_req).has_value()) << "kRaw on EC means a public point, not a private key";
}

// ============================================================================
// File-backed slot loading: the deployment "key_format" property
//
// "raw" / "der" / "pem" force that format; an absent property means the native
// format; any other value fails the load before the key reaches the factory.
// ============================================================================

namespace
{
/// Writes @p bytes to a file under TEST_TMPDIR and returns its absolute path.
std::string WriteTestFile(const std::string& name, const std::vector<std::uint8_t>& bytes)
{
    const char* dir = std::getenv("TEST_TMPDIR");
    const std::string path = std::string{(dir != nullptr) ? dir : "."} + "/" + name;
    std::ofstream out{path, std::ios::binary | std::ios::trunc};
    out.write(reinterpret_cast<const char*>(bytes.data()),  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
              static_cast<std::streamsize>(bytes.size()));
    return path;
}

/// Deploys @p key under a slot for @p algorithm, with the given key_format line
/// (none when @p key_format is std::nullopt).
km::KeySlotConfig DeploySlot(const std::string& name,
                             const std::string& algorithm,
                             const std::vector<std::uint8_t>& key,
                             const std::optional<std::string>& key_format)
{
    const std::string key_path = WriteTestFile(name + ".key", key);
    std::string kv = "[metadata]\navailability=active\n[key]\nkey_path=" + key_path + "\n";
    if (key_format.has_value())
    {
        kv += "key_format=" + key_format.value() + "\n";
    }
    km::KeySlotConfig slot{};
    slot.slot_name = name;
    slot.algorithm = algorithm;
    slot.allowed_operations = score::crypto::KeyOperationPermission::kAll;
    slot.deployment_path = WriteTestFile(name + ".kv", Bytes(kv));
    return slot;
}
}  // namespace

TEST_F(OpenSslKeyHandlerTest, SlotLoad_KeyFormatAbsentOrMatching_Loads)
{
    const std::vector<std::uint8_t> aes(32U, 0x5AU);
    const std::vector<std::uint8_t> hmac(32U, 0xA5U);
    const auto ec_der = ReadVector("/P256-SHA256/siggen_private_key.der");
    const auto ec_pem = ReadVector("/P256-SHA256/siggen_private_key.pem");
    const auto ec_pub_der = ReadP256SpkiDer();
    struct Case
    {
        const char* name;
        const char* algorithm;
        const std::vector<std::uint8_t>* key;
        std::optional<std::string> key_format;
    };
    const std::vector<Case> cases{
        {"aes_native", "AES-256-CBC", &aes, std::nullopt},
        {"aes_raw", "AES-256-CBC", &aes, "raw"},
        {"hmac_native", "HMAC-SHA256", &hmac, std::nullopt},
        {"ec_der_native", "ECDSA-P256-SHA256", &ec_der, std::nullopt},
        {"ec_der", "ECDSA-P256-SHA256", &ec_der, "der"},
        {"ec_pem_native", "ECDSA-P256-SHA256", &ec_pem, std::nullopt},
        {"ec_pem", "ECDSA-P256-SHA256", &ec_pem, "pem"},
        {"ec_pub_der_native", "ECDSA-P256-SHA256", &ec_pub_der, std::nullopt},
    };
    km::FileBackedSlotHandler handler{m_factory};
    for (const auto& c : cases)
    {
        auto result = handler.LoadKey(DeploySlot(c.name, c.algorithm, *c.key, c.key_format));
        ASSERT_TRUE(result.has_value()) << c.name << " failed with error " << ErrorOf(result);
        EXPECT_TRUE(result.value()->Release().has_value());
    }
}

TEST_F(OpenSslKeyHandlerTest, SlotLoad_KeyFormatMismatchOrUnknown_IsRejected)
{
    const std::vector<std::uint8_t> aes(32U, 0x5AU);
    const auto ec_der = ReadVector("/P256-SHA256/siggen_private_key.der");
    struct Case
    {
        const char* name;
        const char* algorithm;
        const std::vector<std::uint8_t>* key;
        const char* key_format;
    };
    for (const auto& c : {Case{"aes_der", "AES-256-CBC", &aes, "der"},
                          Case{"aes_pem", "AES-256-CBC", &aes, "pem"},
                          Case{"aes_bogus", "AES-256-CBC", &aes, "base64"},
                          Case{"aes_upper", "AES-256-CBC", &aes, "RAW"},
                          Case{"ec_pem", "ECDSA-P256-SHA256", &ec_der, "pem"},
                          Case{"ec_bogus", "ECDSA-P256-SHA256", &ec_der, "pkcs8"}})
    {
        km::FileBackedSlotHandler handler{m_factory};
        auto result = handler.LoadKey(DeploySlot(c.name, c.algorithm, *c.key, std::string{c.key_format}));
        ASSERT_FALSE(result.has_value()) << c.name;
        EXPECT_EQ(result.error(), common::DaemonErrorCode::kInvalidFormat) << c.name;
    }
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
    reimp.permissions =
        score::crypto::KeyOperationPermission::kVerify | score::crypto::KeyOperationPermission::kExport;

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

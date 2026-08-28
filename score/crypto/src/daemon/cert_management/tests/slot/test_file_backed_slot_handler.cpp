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

#include "score/crypto/src/daemon/cert_management/slot/file_backed_slot_handler.hpp"
#include "score/crypto/src/daemon/cert_management/tests/test_environment.hpp"
#include "score/crypto/src/daemon/common/storage/kv/kv_deployment_writer.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/cert_management/openssl_cert_parser.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace
{
namespace cert = score::crypto::daemon::cert_management;
namespace provider = score::crypto::daemon::provider::cert_management;
namespace storage = score::crypto::daemon::common::storage;
using Error = score::crypto::daemon::common::DaemonErrorCode;

class FakeParser final : public provider::ICertParser
{
  public:
    score::crypto::Expected<cert::CertObject::Sptr, Error> ParseCertificate(const std::uint8_t* bytes,
                                                                            std::size_t size,
                                                                            score::crypto::FormatType format) override
    {
        if (bytes == nullptr || size == 0U)
            return score::crypto::make_unexpected(Error::kCertificateParsingFailed);
        cert::CertChainMetadata metadata;
        metadata.subject_canonical = "CN=file-test";
        metadata.issuer_canonical = "CN=file-test";
        metadata.fingerprint = std::vector<std::uint8_t>(32U, 0x11U);
        return std::make_shared<cert::CertObject>(
            std::move(metadata), std::vector<std::uint8_t>{bytes, bytes + size}, format);
    }

    score::crypto::Expected<std::vector<cert::CertObject::Sptr>, Error>
    ParseCertificates(const std::uint8_t* bytes, std::size_t size, score::crypto::FormatType format) override
    {
        auto parsed = ParseCertificate(bytes, size, format);
        if (!parsed)
            return score::crypto::make_unexpected(parsed.error());
        return std::vector<cert::CertObject::Sptr>{*parsed};
    }

    score::crypto::Expected<std::int64_t, Error> ValidateCrl(const std::uint8_t*,
                                                             std::size_t,
                                                             score::crypto::FormatType,
                                                             const std::uint8_t*,
                                                             std::size_t,
                                                             score::crypto::FormatType) override
    {
        return 0;
    }
};

class FileBackedSlotHandlerTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        m_directory = cert::test::TempDirectory("score_cert_management_test");
        std::filesystem::create_directories(m_directory);
        m_descriptor = m_directory / "slot.kv";
        m_certificate = m_directory / "certificate.pem";
        m_crl = m_directory / "certificate.crl";

        storage::DeploymentDescriptor descriptor;
        descriptor.Set("certificate", "cert_path", m_certificate.string());
        descriptor.Set("certificate", "cert_format", "pem");
        descriptor.Set("crl", "crl_path", m_crl.string());
        ASSERT_TRUE(storage::KvDeploymentWriter{}.Write(m_descriptor.string(), descriptor).has_value());

        m_slot.deployment_path = m_descriptor.string();
        m_slot.deployment_format = "kv";
        m_handler = std::make_unique<cert::FileBackedSlotHandler>(std::make_shared<FakeParser>());
    }

    void TearDown() override
    {
        std::error_code error;
        std::filesystem::remove_all(m_directory, error);
    }

    std::filesystem::path m_directory;
    std::filesystem::path m_descriptor;
    std::filesystem::path m_certificate;
    std::filesystem::path m_crl;
    cert::CertSlotConfig m_slot;
    std::unique_ptr<cert::FileBackedSlotHandler> m_handler;
};

TEST_F(FileBackedSlotHandlerTest, StoresLoadsAndClearsCertificate)
{
    cert::CertChainMetadata metadata;
    metadata.subject_canonical = "CN=file-test";
    metadata.issuer_canonical = "CN=file-test";
    auto certificate = std::make_shared<cert::CertObject>(
        std::move(metadata), std::vector<std::uint8_t>{1U, 2U, 3U}, score::crypto::FormatType::kDer);

    ASSERT_TRUE(m_handler->StoreCertificate(m_slot, *certificate).has_value());
    ASSERT_TRUE(m_handler->LoadCertificate(m_slot).has_value());
    EXPECT_EQ(m_handler->GetSlotState(m_slot).value(), score::crypto::CertificateSlotState::kOccupied);
    EXPECT_EQ(m_handler->LoadCertificate(m_slot).value()->GetRawBytes().size(), 3U);

    ASSERT_TRUE(m_handler->ClearSlot(m_slot).has_value());
    EXPECT_EQ(m_handler->GetSlotState(m_slot).value(), score::crypto::CertificateSlotState::kEmpty);
}

TEST_F(FileBackedSlotHandlerTest, StoresLoadsAndClearsCrl)
{
    const std::vector<std::uint8_t> crl{4U, 5U, 6U};
    const auto crl_span = score::crypto::span<const std::uint8_t>{crl.data(), crl.size()};
    ASSERT_TRUE(m_handler->StoreCrl(m_slot, crl_span, score::crypto::FormatType::kDer).has_value());
    EXPECT_TRUE(m_handler->HasCrl(m_slot));
    ASSERT_TRUE(m_handler->LoadCrl(m_slot).has_value());
    EXPECT_EQ(*m_handler->LoadCrl(m_slot), crl);

    ASSERT_TRUE(m_handler->ClearCrl(m_slot).has_value());
    EXPECT_FALSE(m_handler->HasCrl(m_slot));
}

// Storing a new certificate must invalidate any existing CRL: the CRL was
// issued for the previous CA key and is meaningless for the new cert.
// After StoreCertificate, HasCrl() must return false even though a CRL was
// stored before the update.
TEST_F(FileBackedSlotHandlerTest, StoreCertificate_ClearsExistingCrl)
{
    cert::CertChainMetadata metadata;
    metadata.subject_canonical = "CN=file-test";
    metadata.issuer_canonical = "CN=file-test";
    auto certificate = std::make_shared<cert::CertObject>(
        std::move(metadata), std::vector<std::uint8_t>{1U, 2U, 3U}, score::crypto::FormatType::kDer);

    // Store a CRL first so the slot has one.
    const std::vector<std::uint8_t> crl_bytes{7U, 8U, 9U};
    ASSERT_TRUE(m_handler
                    ->StoreCrl(m_slot,
                               score::crypto::span<const std::uint8_t>{crl_bytes.data(), crl_bytes.size()},
                               score::crypto::FormatType::kDer)
                    .has_value());
    ASSERT_TRUE(m_handler->HasCrl(m_slot));

    // Storing a new cert must invalidate the stale CRL.
    // crl_path is preserved in the descriptor (for future StoreCrl re-use)
    // but the CRL file is removed, so HasCrl() must return false.
    ASSERT_TRUE(m_handler->StoreCertificate(m_slot, *certificate).has_value());

    EXPECT_FALSE(m_handler->HasCrl(m_slot));  // file gone → FileExists false
    EXPECT_FALSE(std::filesystem::exists(m_crl));

    // crl_path is preserved in the descriptor so a subsequent StoreCrl re-uses
    // the same on-disk location without having to recompute it.
    const std::vector<std::uint8_t> new_crl{0xAAU, 0xBBU};
    ASSERT_TRUE(m_handler
                    ->StoreCrl(m_slot,
                               score::crypto::span<const std::uint8_t>{new_crl.data(), new_crl.size()},
                               score::crypto::FormatType::kDer)
                    .has_value());
    EXPECT_TRUE(m_handler->HasCrl(m_slot));
    EXPECT_TRUE(std::filesystem::exists(m_crl));
}

// A freshly-configured slot with no stored CRL must report HasCrl() == false
// without any prior store call.  This baseline is separate from the
// StoresLoadsAndClearsCrl flow so that a regression in the empty-state
// detection doesn't go unnoticed.
TEST_F(FileBackedSlotHandlerTest, HasCrl_FalseForFreshSlot)
{
    EXPECT_FALSE(m_handler->HasCrl(m_slot));
}

// GetSlotState on a fresh slot must report kEmpty without a prior store.
TEST_F(FileBackedSlotHandlerTest, GetSlotState_EmptyForFreshSlot)
{
    EXPECT_EQ(m_handler->GetSlotState(m_slot).value(), score::crypto::CertificateSlotState::kEmpty);
}

// GetCrlFormat must return kDer (default) when no crl_format key is present in
// the descriptor's [crl] section. The fixture's SetUp writes crl_path but not
// crl_format, so this covers the "key absent" path in CrlHandler::GetCrlFormat.
TEST_F(FileBackedSlotHandlerTest, GetCrlFormat_ReturnsDerWhenNoFormatKey)
{
    EXPECT_EQ(m_handler->GetCrlFormat(m_slot), score::crypto::FormatType::kDer);
}

// After storing a CRL with kPem format, GetCrlFormat must return kPem. This
// verifies that StoreCrl writes the format to the descriptor and GetCrlFormat
// reads it back correctly.
TEST_F(FileBackedSlotHandlerTest, GetCrlFormat_ReadsFormatFromDescriptor)
{
    const std::vector<std::uint8_t> crl{0x01U, 0x02U, 0x03U};
    ASSERT_TRUE(m_handler
                    ->StoreCrl(m_slot,
                               score::crypto::span<const std::uint8_t>{crl.data(), crl.size()},
                               score::crypto::FormatType::kPem)
                    .has_value());
    EXPECT_EQ(m_handler->GetCrlFormat(m_slot), score::crypto::FormatType::kPem);
}

// ClearSlot must be idempotent: calling it a second time on an already-cleared
// slot must return success rather than an error. The FileExists guard ensures
// RemoveFile is not called when the cert file is already absent.
TEST_F(FileBackedSlotHandlerTest, ClearSlot_IsIdempotent)
{
    cert::CertChainMetadata metadata;
    metadata.subject_canonical = "CN=file-test";
    metadata.issuer_canonical = "CN=file-test";
    auto certificate = std::make_shared<cert::CertObject>(
        std::move(metadata), std::vector<std::uint8_t>{1U, 2U, 3U}, score::crypto::FormatType::kDer);

    ASSERT_TRUE(m_handler->StoreCertificate(m_slot, *certificate).has_value());

    ASSERT_TRUE(m_handler->ClearSlot(m_slot).has_value());
    // Second call must succeed — slot is already empty.
    ASSERT_TRUE(m_handler->ClearSlot(m_slot).has_value());
    EXPECT_EQ(m_handler->GetSlotState(m_slot).value(), score::crypto::CertificateSlotState::kEmpty);
}

// ClearCrl must be idempotent: calling it a second time when no CRL file exists
// must return success. The FileExists guard prevents a spurious error from
// RemoveFile on an absent file.
TEST_F(FileBackedSlotHandlerTest, ClearCrl_IsIdempotent)
{
    const std::vector<std::uint8_t> crl{0x0AU, 0x0BU};
    ASSERT_TRUE(m_handler
                    ->StoreCrl(m_slot,
                               score::crypto::span<const std::uint8_t>{crl.data(), crl.size()},
                               score::crypto::FormatType::kDer)
                    .has_value());

    ASSERT_TRUE(m_handler->ClearCrl(m_slot).has_value());
    // Second call must succeed — CRL file is already gone.
    ASSERT_TRUE(m_handler->ClearCrl(m_slot).has_value());
    EXPECT_FALSE(m_handler->HasCrl(m_slot));
}

// ---------------------------------------------------------------------------
// OpenSSL-backed tests — verify real metadata extraction from test vectors.
// These tests require the openssl_backend_active build constraint.
// ---------------------------------------------------------------------------

namespace openssl_ns = score::crypto::daemon::provider::score_provider::openssl;

// Fixture that uses the real OpenSslCertParser and the central test vector.
// This verifies that FileBackedSlotHandler feeds bytes correctly to the parser
// and that the resulting CertObject carries the expected metadata.
class FileBackedSlotHandlerRealParserTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        m_dir = cert::test::TempDirectory("score_cert_slot_real");
        m_descriptor = m_dir / "slot.kv";
        m_cert_file = m_dir / "cert.pem";
        std::filesystem::remove_all(m_dir);
        std::filesystem::create_directories(m_dir);

        ASSERT_TRUE(std::filesystem::copy_file("score/tests/test_vectors/certificate/certificate.pem",
                                               m_cert_file,
                                               std::filesystem::copy_options::overwrite_existing));

        storage::DeploymentDescriptor descriptor;
        descriptor.Set("certificate", "cert_path", m_cert_file.string());
        descriptor.Set("certificate", "cert_format", "pem");
        ASSERT_TRUE(storage::KvDeploymentWriter{}.Write(m_descriptor.string(), descriptor).has_value());

        m_slot.deployment_path = m_descriptor.string();
        m_slot.deployment_format = "kv";

        m_parser = std::make_shared<openssl_ns::OpenSslCertParser>(score::crypto::daemon::common::ProviderId{1U});
        m_handler = std::make_unique<cert::FileBackedSlotHandler>(m_parser);
    }

    void TearDown() override
    {
        std::error_code ec;
        std::filesystem::remove_all(m_dir, ec);
    }

    std::filesystem::path m_dir;
    std::filesystem::path m_descriptor;
    std::filesystem::path m_cert_file;
    cert::CertSlotConfig m_slot;
    std::shared_ptr<openssl_ns::OpenSslCertParser> m_parser;
    std::unique_ptr<cert::FileBackedSlotHandler> m_handler;
};

// LoadCertificate must return a CertObject whose metadata matches the
// known-answer values recorded in certificate_manifest.json.
TEST_F(FileBackedSlotHandlerRealParserTest, LoadCertificate_MetadataMatchesTestVector)
{
    const auto result = m_handler->LoadCertificate(m_slot);
    ASSERT_TRUE(result.has_value());
    ASSERT_NE(*result, nullptr);

    const auto& cert = **result;
    EXPECT_EQ(cert.GetSubject(), "CN=cert-management-test,O=Eclipse");
    EXPECT_EQ(cert.GetIssuer(), "CN=cert-management-test,O=Eclipse");
    EXPECT_TRUE(cert.IsCA());
    // SKID extension is present in the test vector (20 bytes for a SHA-1 key ID).
    EXPECT_EQ(cert.GetSkid().size(), 20U);
    // SHA-256 fingerprint is always 32 bytes.
    EXPECT_EQ(cert.GetFingerprint().size(), 32U);
}

// Storing a cert then loading it back must round-trip subject and CA flag
// using a fresh handler instance to exclude any in-memory cache effects.
TEST_F(FileBackedSlotHandlerRealParserTest, StoreThenLoad_SubjectAndIsCAMatch)
{
    // Load the initial cert to get a CertObject to store.
    const auto initial = m_handler->LoadCertificate(m_slot);
    ASSERT_TRUE(initial.has_value());

    // Store it back (overwrites the same path, which is fine for this test).
    ASSERT_TRUE(m_handler->StoreCertificate(m_slot, **initial).has_value());

    // Load with a fresh handler to avoid any in-memory state.
    cert::FileBackedSlotHandler fresh_handler{m_parser};
    const auto reloaded = fresh_handler.LoadCertificate(m_slot);
    ASSERT_TRUE(reloaded.has_value());

    EXPECT_EQ((*reloaded)->GetSubject(), (*initial)->GetSubject());
    EXPECT_EQ((*reloaded)->IsCA(), (*initial)->IsCA());
}

// ---------------------------------------------------------------------------
// Algorithm-variety parameterized tests
//
// Verify that OpenSslCertParser correctly parses every certificate in the
// test-vector suite: RSA (2048/3072/4096), EC (P-256/P-384/P-521),
// EdDSA (Ed25519/Ed448), and PQC (ML-DSA-44/65/87).
//
// Each test copies the PEM from the test-vector directory into a temp
// directory, sets up a FileBackedSlotHandler with a real OpenSslCertParser,
// and verifies common metadata invariants that must hold for every cert:
//   - Subject matches the manifest's expected value
//   - CA flag is set (all test-vector certs are self-signed CAs)
//   - SKID is present and 20 bytes (SHA-1 key ID, algorithm-independent)
//   - SHA-256 fingerprint is 32 bytes (algorithm-independent)
// ---------------------------------------------------------------------------

struct AlgorithmVarietyParam
{
    const char* pem_path;          // workspace-relative path to the PEM test vector
    const char* expected_subject;  // RFC 4514 DN as returned by GetSubject()
};

class FileBackedSlotHandlerAlgorithmVarietyTest : public ::testing::TestWithParam<AlgorithmVarietyParam>
{
  protected:
    void SetUp() override
    {
        m_dir = cert::test::TempDirectory("score_cert_alg_variety");
        std::filesystem::remove_all(m_dir);
        std::filesystem::create_directories(m_dir);

        const auto& p = GetParam();
        m_cert_file = m_dir / "cert.pem";
        ASSERT_TRUE(
            std::filesystem::copy_file(p.pem_path, m_cert_file, std::filesystem::copy_options::overwrite_existing))
            << "Failed to copy test vector: " << p.pem_path;

        const auto descriptor_path = m_dir / "slot.kv";
        storage::DeploymentDescriptor descriptor;
        descriptor.Set("certificate", "cert_path", m_cert_file.string());
        descriptor.Set("certificate", "cert_format", "pem");
        ASSERT_TRUE(storage::KvDeploymentWriter{}.Write(descriptor_path.string(), descriptor).has_value());

        m_slot.deployment_path = descriptor_path.string();
        m_slot.deployment_format = "kv";

        m_parser = std::make_shared<openssl_ns::OpenSslCertParser>(score::crypto::daemon::common::ProviderId{1U});
        m_handler = std::make_unique<cert::FileBackedSlotHandler>(m_parser);
    }

    void TearDown() override
    {
        std::error_code ec;
        std::filesystem::remove_all(m_dir, ec);
    }

    std::filesystem::path m_dir;
    std::filesystem::path m_cert_file;
    cert::CertSlotConfig m_slot;
    std::shared_ptr<openssl_ns::OpenSslCertParser> m_parser;
    std::unique_ptr<cert::FileBackedSlotHandler> m_handler;
};

TEST_P(FileBackedSlotHandlerAlgorithmVarietyTest, LoadCertificate_MetadataIsCorrect)
{
    const auto& p = GetParam();
    const auto result = m_handler->LoadCertificate(m_slot);
    ASSERT_TRUE(result.has_value()) << "LoadCertificate failed for: " << p.pem_path;
    ASSERT_NE(*result, nullptr);

    const auto& c = **result;
    EXPECT_EQ(c.GetSubject(), p.expected_subject);
    EXPECT_TRUE(c.IsCA());
    // SKID is SHA-1(public key) — 20 bytes regardless of signature algorithm.
    EXPECT_EQ(c.GetSkid().size(), 20U) << "Unexpected SKID size for: " << p.pem_path;
    // SHA-256 fingerprint is always 32 bytes — independent of cert algorithm.
    EXPECT_EQ(c.GetFingerprint().size(), 32U) << "Unexpected fingerprint size for: " << p.pem_path;
}

// clang-format off
INSTANTIATE_TEST_SUITE_P(
    AlgorithmVariety,
    FileBackedSlotHandlerAlgorithmVarietyTest,
    ::testing::Values(
        // RSA
        AlgorithmVarietyParam{"score/tests/test_vectors/certificate/certificate.pem",
                              "CN=cert-management-test,O=Eclipse"},
        AlgorithmVarietyParam{"score/tests/test_vectors/certificate/rsa_3072.pem",
                              "CN=cert-mgmt-rsa-3072,O=Eclipse"},
        AlgorithmVarietyParam{"score/tests/test_vectors/certificate/rsa_4096.pem",
                              "CN=cert-mgmt-rsa-4096,O=Eclipse"},
        // EC
        AlgorithmVarietyParam{"score/tests/test_vectors/certificate/ec_p256.pem",
                              "CN=cert-mgmt-ec-p256,O=Eclipse"},
        AlgorithmVarietyParam{"score/tests/test_vectors/certificate/ec_p384.pem",
                              "CN=cert-mgmt-ec-p384,O=Eclipse"},
        AlgorithmVarietyParam{"score/tests/test_vectors/certificate/ec_p521.pem",
                              "CN=cert-mgmt-ec-p521,O=Eclipse"},
        // EdDSA
        AlgorithmVarietyParam{"score/tests/test_vectors/certificate/ed25519.pem",
                              "CN=cert-mgmt-ed25519,O=Eclipse"},
        AlgorithmVarietyParam{"score/tests/test_vectors/certificate/ed448.pem",
                              "CN=cert-mgmt-ed448,O=Eclipse"},
        // PQC — ML-DSA (NIST FIPS 204)
        AlgorithmVarietyParam{"score/tests/test_vectors/certificate/ml_dsa_44.pem",
                              "CN=cert-mgmt-ml-dsa-44,O=Eclipse"},
        AlgorithmVarietyParam{"score/tests/test_vectors/certificate/ml_dsa_65.pem",
                              "CN=cert-mgmt-ml-dsa-65,O=Eclipse"},
        AlgorithmVarietyParam{"score/tests/test_vectors/certificate/ml_dsa_87.pem",
                              "CN=cert-mgmt-ml-dsa-87,O=Eclipse"}
    ),
    [](const ::testing::TestParamInfo<AlgorithmVarietyParam>& info) {
        // Build a test name from the PEM filename stem (e.g. "rsa_3072").
        std::string name = info.param.pem_path;
        const auto slash = name.rfind('/');
        if (slash != std::string::npos)
            name = name.substr(slash + 1U);
        const auto dot = name.rfind('.');
        if (dot != std::string::npos)
            name = name.substr(0U, dot);
        return name;
    }
);
// clang-format on

}  // namespace

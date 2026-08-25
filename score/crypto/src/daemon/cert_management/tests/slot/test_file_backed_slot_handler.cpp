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
};

class FileBackedSlotHandlerTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        m_directory = std::filesystem::temp_directory_path() / "score_cert_management_test";
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
        m_dir = std::filesystem::temp_directory_path() / "score_cert_slot_real";
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
}  // namespace

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

    score::crypto::Expected<std::vector<std::uint8_t>, Error> EncodeCertificate(const cert::CertObject&,
                                                                                score::crypto::FormatType) override
    {
        return score::crypto::make_unexpected(Error::kUnsupportedOperation);
    }

    score::crypto::Expected<score::crypto::CrlMetadata, Error> ValidateCrl(const std::uint8_t*,
                                                                           std::size_t,
                                                                           score::crypto::FormatType,
                                                                           const std::uint8_t*,
                                                                           std::size_t,
                                                                           score::crypto::FormatType) override
    {
        return score::crypto::CrlMetadata{};
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
    ASSERT_TRUE(m_handler->HasCrl(m_slot).has_value());
    EXPECT_TRUE(m_handler->HasCrl(m_slot).value());
    ASSERT_TRUE(m_handler->LoadCrl(m_slot).has_value());
    EXPECT_EQ(*m_handler->LoadCrl(m_slot), crl);

    ASSERT_TRUE(m_handler->ClearCrl(m_slot).has_value());
    ASSERT_TRUE(m_handler->HasCrl(m_slot).has_value());
    EXPECT_FALSE(m_handler->HasCrl(m_slot).value());
}

TEST_F(FileBackedSlotHandlerTest, DerivesMetadataForPreconfiguredCrlWithoutCachedMetadata)
{
    cert::CertChainMetadata certificate_metadata;
    certificate_metadata.subject_canonical = "CN=file-test";
    certificate_metadata.issuer_canonical = "CN=file-test";
    auto certificate = std::make_shared<cert::CertObject>(
        std::move(certificate_metadata), std::vector<std::uint8_t>{1U, 2U, 3U}, score::crypto::FormatType::kDer);
    ASSERT_TRUE(m_handler->StoreCertificate(m_slot, *certificate).has_value());

    const std::vector<std::uint8_t> crl{4U, 5U, 6U};
    ASSERT_TRUE(m_handler
                    ->StoreCrl(m_slot,
                               score::crypto::span<const std::uint8_t>{crl.data(), crl.size()},
                               score::crypto::FormatType::kDer)
                    .has_value());

    const auto metadata = m_handler->GetCrlMetadata(m_slot);
    ASSERT_TRUE(metadata.has_value());
    EXPECT_EQ(metadata->this_update, 0);
    EXPECT_EQ(metadata->next_update, 0);
    EXPECT_EQ(metadata->crl_number, 0U);
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
    ASSERT_TRUE(m_handler->HasCrl(m_slot).has_value());
    ASSERT_TRUE(m_handler->HasCrl(m_slot).value());

    // Storing a new cert must invalidate the stale CRL.
    // crl_path is preserved in the descriptor (for future StoreCrl re-use)
    // but the CRL file is removed, so HasCrl() must return false.
    ASSERT_TRUE(m_handler->StoreCertificate(m_slot, *certificate).has_value());

    ASSERT_TRUE(m_handler->HasCrl(m_slot).has_value());
    EXPECT_FALSE(m_handler->HasCrl(m_slot).value());
    EXPECT_FALSE(std::filesystem::exists(m_crl));

    // crl_path is preserved in the descriptor so a subsequent StoreCrl re-uses
    // the same on-disk location without having to recompute it.
    const std::vector<std::uint8_t> new_crl{0xAAU, 0xBBU};
    ASSERT_TRUE(m_handler
                    ->StoreCrl(m_slot,
                               score::crypto::span<const std::uint8_t>{new_crl.data(), new_crl.size()},
                               score::crypto::FormatType::kDer)
                    .has_value());
    ASSERT_TRUE(m_handler->HasCrl(m_slot).has_value());
    EXPECT_TRUE(m_handler->HasCrl(m_slot).value());
    EXPECT_TRUE(std::filesystem::exists(m_crl));
}

// A freshly-configured slot with no stored CRL must report HasCrl() == false
// without any prior store call.  This baseline is separate from the
// StoresLoadsAndClearsCrl flow so that a regression in the empty-state
// detection doesn't go unnoticed.
TEST_F(FileBackedSlotHandlerTest, HasCrl_FalseForFreshSlot)
{
    ASSERT_TRUE(m_handler->HasCrl(m_slot).has_value());
    EXPECT_FALSE(m_handler->HasCrl(m_slot).value());
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
    ASSERT_TRUE(m_handler->HasCrl(m_slot).has_value());
    EXPECT_FALSE(m_handler->HasCrl(m_slot).value());
}

// StoreCrl without metadata must not write a crl_next_update key to the descriptor.
TEST_F(FileBackedSlotHandlerTest, StoreCrl_WithoutMetadata_DoesNotWriteNextUpdateKey)
{
    const std::vector<std::uint8_t> crl{0x01U, 0x02U};
    ASSERT_TRUE(m_handler
                    ->StoreCrl(m_slot,
                               score::crypto::span<const std::uint8_t>{crl.data(), crl.size()},
                               score::crypto::FormatType::kDer)
                    .has_value());

    const auto nu = m_handler->GetCrlNextUpdate(m_slot);
    EXPECT_FALSE(nu.has_value());
    EXPECT_EQ(nu.error(), Error::kResourceNotAllocated);
}

// StoreCrl with validated metadata must persist nextUpdate and expose it
// through the existing freshness query.
TEST_F(FileBackedSlotHandlerTest, StoreCrl_MetadataPersistsNextUpdate)
{
    constexpr std::int64_t kEpoch = 1800000000LL;
    const std::vector<std::uint8_t> crl{0x03U, 0x04U};
    score::crypto::CrlMetadata metadata;
    metadata.next_update = kEpoch;
    ASSERT_TRUE(m_handler
                    ->StoreCrl(m_slot,
                               score::crypto::span<const std::uint8_t>{crl.data(), crl.size()},
                               score::crypto::FormatType::kDer,
                               metadata)
                    .has_value());

    const auto nu = m_handler->GetCrlNextUpdate(m_slot);
    ASSERT_TRUE(nu.has_value());
    EXPECT_EQ(*nu, kEpoch);
}

// GetCrlNextUpdate with a malformed value in the descriptor must return
// kInvalidArgument and must not throw or call std::terminate.
TEST_F(FileBackedSlotHandlerTest, GetCrlNextUpdate_MalformedValue_ReturnsInvalidArgument)
{
    // Write an intentionally invalid epoch string directly to the descriptor.
    storage::DeploymentDescriptor descriptor;
    descriptor.Set("certificate", "cert_path", m_certificate.string());
    descriptor.Set("certificate", "cert_format", "pem");
    descriptor.Set("crl", "crl_path", m_crl.string());
    descriptor.Set("crl", "crl_next_update", "not_a_number");
    ASSERT_TRUE(storage::KvDeploymentWriter{}.Write(m_descriptor.string(), descriptor).has_value());

    const auto nu = m_handler->GetCrlNextUpdate(m_slot);
    EXPECT_FALSE(nu.has_value());
    EXPECT_EQ(nu.error(), Error::kInvalidArgument);
}

}  // namespace

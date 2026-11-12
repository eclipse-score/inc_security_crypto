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
#include "score/crypto/src/daemon/cert_management/slot/deployment_loader.hpp"
#include "score/crypto/src/daemon/cert_management/tests/test_environment.hpp"
#include "score/crypto/src/daemon/common/storage/file_io.hpp"
#include "score/crypto/src/daemon/common/storage/kv/kv_deployment_writer.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/cert_management/openssl_cert_parser.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace
{
namespace cert = score::crypto::daemon::cert_management;
namespace storage = score::crypto::daemon::common::storage;
namespace openssl_ns = score::crypto::daemon::provider::score_provider::openssl;
using Error = score::crypto::daemon::common::DaemonErrorCode;

// Independently obtained with openssl x509 -fingerprint -sha256 from the basic
// certificate.pem fixture. This is SHA-256 of DER, not SHA-256 of the PEM text.
constexpr char kBasicCertificateHash[] = "3e7a581bcaab80f73535b10968f8c3e68517194b6a404ce5f58aacabe0a62d0c";
constexpr char kBasicCertificateHashUpper[] = "3E7A581BCAAB80F73535B10968F8C3E68517194B6A404CE5F58AACABE0A62D0C";
static_assert(sizeof(kBasicCertificateHash) - 1U == 64U);
static_assert(sizeof(kBasicCertificateHashUpper) - 1U == 64U);

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

        ASSERT_TRUE(std::filesystem::copy_file("score/tests/test_vectors/certificate/basic/certificate.pem",
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

    void SetDescriptorHash(const std::string& hash)
    {
        auto descriptor = cert::DeploymentLoader::Load(m_descriptor.string(), "kv");
        ASSERT_TRUE(descriptor.has_value());
        descriptor->Set("certificate", "cert_hash", hash);
        ASSERT_TRUE(storage::KvDeploymentWriter{}.Write(m_descriptor.string(), *descriptor).has_value());
    }

    void SetRawDescriptorHash(const std::string& hash)
    {
        // Deliberately malformed on-disk input must bypass the validated writer,
        // which rejects values such as trailing whitespace before writing them.
        const auto content =
            "[certificate]\ncert_path=" + m_cert_file.string() + "\ncert_format=pem\ncert_hash=" + hash + "\n";
        const std::vector<std::uint8_t> bytes(content.begin(), content.end());
        ASSERT_TRUE(storage::WriteFile(m_descriptor.string(), bytes).has_value());
    }

    void RequireIntegrity()
    {
        m_slot.integrity_policy = cert::IntegrityPolicy::kRequired;
    }

    std::filesystem::path m_dir;
    std::filesystem::path m_descriptor;
    std::filesystem::path m_cert_file;
    cert::CertSlotConfig m_slot;
    std::shared_ptr<openssl_ns::OpenSslCertParser> m_parser;
    std::unique_ptr<cert::FileBackedSlotHandler> m_handler;
};

TEST_F(FileBackedSlotHandlerRealParserTest, LoadCertificate_MetadataMatchesTestVector)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_management__parse");
    RecordProperty("Description",
                   "Loads a certificate through ICertParser and verifies the parsed CertObject metadata.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto result = m_handler->LoadCertificate(m_slot);
    ASSERT_TRUE(result.has_value());
    ASSERT_NE(*result, nullptr);

    const auto& cert = **result;
    EXPECT_EQ(cert.GetSubject(), "CN=cert-management-test,O=Eclipse");
    EXPECT_EQ(cert.GetIssuer(), "CN=cert-management-test,O=Eclipse");
    EXPECT_TRUE(cert.IsCA());
    EXPECT_EQ(cert.GetSkid().size(), 20U);
    EXPECT_EQ(cert.GetFingerprint().size(), 32U);
}

TEST_F(FileBackedSlotHandlerRealParserTest, StoreThenLoad_SubjectAndIsCAMatch)
{
    const auto initial = m_handler->LoadCertificate(m_slot);
    ASSERT_TRUE(initial.has_value());
    ASSERT_TRUE(m_handler->StoreCertificate(m_slot, **initial).has_value());

    cert::FileBackedSlotHandler fresh_handler{m_parser};
    const auto reloaded = fresh_handler.LoadCertificate(m_slot);
    ASSERT_TRUE(reloaded.has_value());

    EXPECT_EQ((*reloaded)->GetSubject(), (*initial)->GetSubject());
    EXPECT_EQ((*reloaded)->IsCA(), (*initial)->IsCA());
}

TEST_F(FileBackedSlotHandlerRealParserTest, RequiredIntegrity_AcceptsHexWithoutCaseRestrictions)
{
    RequireIntegrity();
    const std::vector<std::string> hashes{kBasicCertificateHash,
                                          kBasicCertificateHashUpper,
                                          "3e7A581bCaAB80f73535B10968F8c3E68517194b6A404Ce5F58aACaBe0a62D0c"};
    for (const auto& hash : hashes)
    {
        SCOPED_TRACE(hash);
        SetDescriptorHash(hash);
        const auto loaded = m_handler->LoadCertificate(m_slot);
        ASSERT_TRUE(loaded.has_value());
        ASSERT_NE(*loaded, nullptr);
        EXPECT_EQ((*loaded)->GetSubject(), "CN=cert-management-test,O=Eclipse");
    }
}

TEST_F(FileBackedSlotHandlerRealParserTest, RequiredIntegrity_RejectsAbsentHash)
{
    RequireIntegrity();
    const auto loaded = m_handler->LoadCertificate(m_slot);
    ASSERT_FALSE(loaded.has_value());
    EXPECT_EQ(loaded.error(), Error::kInvalidArgument);
}

TEST_F(FileBackedSlotHandlerRealParserTest, RequiredIntegrity_RejectsMalformedAndMismatchedHashes)
{
    RequireIntegrity();
    const std::vector<std::string> hashes{"",
                                          std::string(63U, '0'),
                                          std::string(65U, '0'),
                                          std::string(64U, 'g'),
                                          "0x" + std::string{kBasicCertificateHash},
                                          std::string{kBasicCertificateHash}.substr(0U, 63U) + ":",
                                          std::string{kBasicCertificateHash}.substr(0U, 63U) + " ",
                                          std::string{kBasicCertificateHash}.substr(0U, 63U) + "d"};
    for (const auto& hash : hashes)
    {
        SCOPED_TRACE(hash);
        ASSERT_NO_FATAL_FAILURE(SetRawDescriptorHash(hash));
        const auto loaded = m_handler->LoadCertificate(m_slot);
        ASSERT_FALSE(loaded.has_value());
        EXPECT_EQ(loaded.error(), Error::kInvalidArgument);
    }
}

TEST_F(FileBackedSlotHandlerRealParserTest, RequiredIntegrity_RejectsChangedCertificateBytes)
{
    SetDescriptorHash(kBasicCertificateHash);
    RequireIntegrity();
    ASSERT_TRUE(m_handler->LoadCertificate(m_slot).has_value());
    // Substitute another parseable certificate without changing the descriptor.
    ASSERT_TRUE(std::filesystem::copy_file("score/tests/test_vectors/certificate/algorithm_variety/rsa_3072.pem",
                                           m_cert_file,
                                           std::filesystem::copy_options::overwrite_existing));
    const auto loaded = m_handler->LoadCertificate(m_slot);
    ASSERT_FALSE(loaded.has_value());
    EXPECT_EQ(loaded.error(), Error::kInvalidArgument);
}

TEST_F(FileBackedSlotHandlerRealParserTest, RequiredIntegrity_IgnoresPemLineEndingDifferences)
{
    SetDescriptorHash(kBasicCertificateHash);
    RequireIntegrity();
    const auto original = storage::ReadFile(m_cert_file.string(), cert::FileBackedSlotHandler::kMaxCertSize);
    ASSERT_TRUE(original.has_value());
    std::vector<std::uint8_t> crlf;
    for (const auto byte : *original)
    {
        if (byte == '\n')
        {
            crlf.push_back('\r');
        }
        crlf.push_back(byte);
    }
    ASSERT_NE(crlf, *original);
    ASSERT_TRUE(storage::WriteFile(m_cert_file.string(), crlf).has_value());
    const auto loaded = m_handler->LoadCertificate(m_slot);
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ((*loaded)->GetRawBytes().size(), crlf.size());
}

TEST_F(FileBackedSlotHandlerRealParserTest, RequiredIntegrity_PropagatesCertificateParseFailure)
{
    SetDescriptorHash(kBasicCertificateHash);
    RequireIntegrity();
    const std::vector<std::uint8_t> invalid_bytes{1U, 2U, 3U};
    ASSERT_TRUE(storage::WriteFile(m_cert_file.string(), invalid_bytes).has_value());
    const auto loaded = m_handler->LoadCertificate(m_slot);
    ASSERT_FALSE(loaded.has_value());
    EXPECT_EQ(loaded.error(), Error::kCertificateParsingFailed);
}

TEST_F(FileBackedSlotHandlerRealParserTest, DisabledIntegrity_IgnoresDescriptorHash)
{
    for (const auto& hash : {std::string{}, std::string{"not-hex"}, std::string(64U, '0')})
    {
        SetDescriptorHash(hash);
        EXPECT_TRUE(m_handler->LoadCertificate(m_slot).has_value());
    }
}

TEST_F(FileBackedSlotHandlerRealParserTest, StoreCertificate_UpdatesHash)
{
    const auto parsed = m_handler->LoadCertificate(m_slot);
    ASSERT_TRUE(parsed.has_value());
    SetDescriptorHash(std::string(64U, '0'));
    RequireIntegrity();
    ASSERT_TRUE(m_handler->StoreCertificate(m_slot, **parsed).has_value());
    const auto descriptor = cert::DeploymentLoader::Load(m_descriptor.string(), "kv");
    ASSERT_TRUE(descriptor.has_value());
    EXPECT_EQ(descriptor->Get("certificate", "cert_hash"), kBasicCertificateHash);
    EXPECT_EQ(descriptor->Get("certificate", "cert_path"), m_cert_file.string());
    EXPECT_EQ(descriptor->Get("certificate", "cert_format"), "pem");
    ASSERT_TRUE(m_handler->LoadCertificate(m_slot).has_value());
}

TEST_F(FileBackedSlotHandlerRealParserTest, StoreCertificate_DerAndPemShareCanonicalDerHash)
{
    const auto pem = m_handler->LoadCertificate(m_slot);
    ASSERT_TRUE(pem.has_value());
    // Hash maintenance is independent of policy enablement.
    ASSERT_TRUE(m_handler->StoreCertificate(m_slot, **pem).has_value());
    auto descriptor = cert::DeploymentLoader::Load(m_descriptor.string(), "kv");
    ASSERT_TRUE(descriptor.has_value());
    EXPECT_EQ(descriptor->Get("certificate", "cert_hash"), kBasicCertificateHash);

    const auto der_bytes = m_parser->EncodeCertificate(**pem, score::crypto::FormatType::kDer);
    ASSERT_TRUE(der_bytes.has_value());
    const auto der = m_parser->ParseCertificate(der_bytes->data(), der_bytes->size(), score::crypto::FormatType::kDer);
    ASSERT_TRUE(der.has_value());
    RequireIntegrity();
    ASSERT_TRUE(m_handler->StoreCertificate(m_slot, **der).has_value());
    descriptor = cert::DeploymentLoader::Load(m_descriptor.string(), "kv");
    ASSERT_TRUE(descriptor.has_value());
    EXPECT_EQ(descriptor->Get("certificate", "cert_hash"), kBasicCertificateHash);
    EXPECT_EQ(descriptor->Get("certificate", "cert_format"), "der");
    const auto loaded = m_handler->LoadCertificate(m_slot);
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ((*loaded)->GetFormat(), score::crypto::FormatType::kDer);
}

struct AlgorithmVarietyParam
{
    const char* pem_path;
    const char* expected_subject;
};

class FileBackedSlotHandlerAlgorithmVarietyTest : public ::testing::TestWithParam<AlgorithmVarietyParam>
{
  protected:
    void SetUp() override
    {
        m_dir = cert::test::TempDirectory("score_cert_alg_variety");
        std::filesystem::remove_all(m_dir);
        std::filesystem::create_directories(m_dir);

        const auto& param = GetParam();
        m_cert_file = m_dir / "cert.pem";
        ASSERT_TRUE(
            std::filesystem::copy_file(param.pem_path, m_cert_file, std::filesystem::copy_options::overwrite_existing))
            << "Failed to copy test vector: " << param.pem_path;

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
    const auto& param = GetParam();
    const auto result = m_handler->LoadCertificate(m_slot);
    ASSERT_TRUE(result.has_value()) << "LoadCertificate failed for: " << param.pem_path;
    ASSERT_NE(*result, nullptr);

    const auto& cert = **result;
    EXPECT_EQ(cert.GetSubject(), param.expected_subject);
    EXPECT_TRUE(cert.IsCA());
    EXPECT_EQ(cert.GetSkid().size(), 20U) << "Unexpected SKID size for: " << param.pem_path;
    EXPECT_EQ(cert.GetFingerprint().size(), 32U) << "Unexpected fingerprint size for: " << param.pem_path;
}

// clang-format off
INSTANTIATE_TEST_SUITE_P(
    AlgorithmVariety,
    FileBackedSlotHandlerAlgorithmVarietyTest,
    ::testing::Values(
        AlgorithmVarietyParam{"score/tests/test_vectors/certificate/basic/certificate.pem",
                              "CN=cert-management-test,O=Eclipse"},
        AlgorithmVarietyParam{"score/tests/test_vectors/certificate/algorithm_variety/rsa_3072.pem",
                              "CN=cert-mgmt-rsa-3072,O=Eclipse"},
        AlgorithmVarietyParam{"score/tests/test_vectors/certificate/algorithm_variety/rsa_4096.pem",
                              "CN=cert-mgmt-rsa-4096,O=Eclipse"},
        AlgorithmVarietyParam{"score/tests/test_vectors/certificate/algorithm_variety/ec_p256.pem",
                              "CN=cert-mgmt-ec-p256,O=Eclipse"},
        AlgorithmVarietyParam{"score/tests/test_vectors/certificate/algorithm_variety/ec_p384.pem",
                              "CN=cert-mgmt-ec-p384,O=Eclipse"},
        AlgorithmVarietyParam{"score/tests/test_vectors/certificate/algorithm_variety/ec_p521.pem",
                              "CN=cert-mgmt-ec-p521,O=Eclipse"},
        AlgorithmVarietyParam{"score/tests/test_vectors/certificate/algorithm_variety/ed25519.pem",
                              "CN=cert-mgmt-ed25519,O=Eclipse"},
        AlgorithmVarietyParam{"score/tests/test_vectors/certificate/algorithm_variety/ed448.pem",
                              "CN=cert-mgmt-ed448,O=Eclipse"},
        AlgorithmVarietyParam{"score/tests/test_vectors/certificate/algorithm_variety/ml_dsa_44.pem",
                              "CN=cert-mgmt-ml-dsa-44,O=Eclipse"},
        AlgorithmVarietyParam{"score/tests/test_vectors/certificate/algorithm_variety/ml_dsa_65.pem",
                              "CN=cert-mgmt-ml-dsa-65,O=Eclipse"},
        AlgorithmVarietyParam{"score/tests/test_vectors/certificate/algorithm_variety/ml_dsa_87.pem",
                              "CN=cert-mgmt-ml-dsa-87,O=Eclipse"}
    ),
    [](const ::testing::TestParamInfo<AlgorithmVarietyParam>& info) {
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

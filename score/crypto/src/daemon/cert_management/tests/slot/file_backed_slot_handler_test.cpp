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
#include <vector>

namespace
{
namespace cert = score::crypto::daemon::cert_management;
namespace storage = score::crypto::daemon::common::storage;
namespace openssl_ns = score::crypto::daemon::provider::score_provider::openssl;

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

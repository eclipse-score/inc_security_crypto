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

#include "score/crypto/src/daemon/cert_management/slot/crl_handler.hpp"
#include "score/crypto/src/daemon/common/storage/kv/kv_deployment_writer.hpp"
#include "score/tests/utility/test_utility.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace
{
namespace cert = score::crypto::daemon::cert_management;
namespace storage = score::crypto::daemon::common::storage;

class CrlHandlerTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        m_directory = ::tests::utility::TempDirectory("score_crl_handler_test");
        std::filesystem::create_directories(m_directory);
        m_descriptor = m_directory / "slot.kv";
        m_crl = m_directory / "certificate.crl";

        std::ofstream crl_file{m_crl, std::ios::binary};
        crl_file.write(reinterpret_cast<const char*>(m_crl_bytes.data()),
                       static_cast<std::streamsize>(m_crl_bytes.size()));
        crl_file.close();

        m_slot.deployment_path = m_descriptor.string();
        m_slot.deployment_format = "kv";
    }

    void TearDown() override
    {
        std::error_code error;
        std::filesystem::remove_all(m_directory, error);
    }

    /// Writes a [crl] section whose only variable field is @p next_update.
    void WriteDescriptor(const std::string& next_update)
    {
        storage::DeploymentDescriptor descriptor;
        descriptor.Set("crl", "crl_path", m_crl.string());
        descriptor.Set("crl", "crl_format", "der");
        descriptor.Set("crl", "crl_fingerprint", std::string(64U, 'a'));
        descriptor.Set("crl", "crl_issuer_fingerprint", std::string(64U, 'b'));
        descriptor.Set("crl", "crl_this_update", "100");
        descriptor.Set("crl", "crl_next_update", next_update);
        descriptor.Set("crl", "crl_number", "7");
        ASSERT_TRUE(storage::KvDeploymentWriter{}.Write(m_descriptor.string(), descriptor).has_value());
    }

    const std::vector<std::uint8_t> m_crl_bytes{1U, 2U, 3U};
    std::filesystem::path m_directory;
    std::filesystem::path m_descriptor;
    std::filesystem::path m_crl;
    cert::CertSlotConfig m_slot;
    cert::CrlHandler m_handler;
};

TEST_F(CrlHandlerTest, GetCrlMetadata_WellFormedFields_ReturnsMetadata)
{
    WriteDescriptor("200");

    const auto result = m_handler.GetCrlMetadata(m_slot);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->has_value());
    EXPECT_EQ((*result)->this_update, 100);
    EXPECT_EQ((*result)->next_update, 200);
    EXPECT_EQ((*result)->crl_number, 7U);
}

// A malformed cached value is treated as absent: the call succeeds with no metadata
// rather than returning an error or throwing.
TEST_F(CrlHandlerTest, GetCrlMetadata_MalformedNextUpdate_ReturnsNoMetadata)
{
    WriteDescriptor("not_a_number");

    const auto result = m_handler.GetCrlMetadata(m_slot);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->has_value());
}

// The CRL bytes remain readable when the cached metadata is malformed.
TEST_F(CrlHandlerTest, LoadCrlData_MalformedNextUpdate_ReturnsBytesWithoutMetadata)
{
    WriteDescriptor("not_a_number");

    const auto crl = m_handler.LoadCrlData(m_slot);
    ASSERT_TRUE(crl.has_value());
    ASSERT_TRUE(crl->has_value());
    EXPECT_EQ((*crl)->bytes, m_crl_bytes);
    EXPECT_EQ((*crl)->format, score::crypto::FormatType::kDer);
    EXPECT_FALSE((*crl)->metadata.has_value());
}

}  // namespace

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

#include "score/crypto/src/daemon/cert_management/cert_management_module.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/config/inc/config.hpp"
#include "score/crypto/src/daemon/config/src/flatbuffer_config_parser.hpp"
#include "score/crypto/src/daemon/provider/provider_manager.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/provider_openssl.hpp"

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <string_view>

namespace cert = score::crypto::daemon::cert_management;
namespace common = score::crypto::daemon::common;
namespace config = score::crypto::daemon::config;
namespace openssl = score::crypto::daemon::provider::score_provider::openssl;
namespace provider = score::crypto::daemon::provider;

namespace
{
constexpr std::string_view kConfigPath = "score/crypto/tests/cert_management/config/cert_module_startup_config.bin";
constexpr std::string_view kConfiguredProviderName = "OPENSSL";

class CertModuleStartupTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        const auto file = config::FlatBufferConfigParser::LoadFile(kConfigPath);
        ASSERT_TRUE(file.has_value()) << "Failed to load config file: " << kConfigPath;

        const auto parse_result = config::FlatBufferConfigParser::ParseCertManagementConfig(file.value(), m_config);
        ASSERT_TRUE(parse_result.has_value()) << "Failed to parse cert config from: " << kConfigPath;
        ASSERT_TRUE(parse_result.value()) << "Cert config section is absent in: " << kConfigPath;
        ASSERT_EQ(m_config.GetParserProviderName(), kConfiguredProviderName);
    }

    config::CertificateConfig m_config;
};

TEST_F(CertModuleStartupTest, StartsWithConfiguredParserProvider)
{
    auto manager = std::make_shared<provider::ProviderManager>(config::ProviderInitConfig{});
    auto configured_provider = std::make_shared<openssl::OpenSSL>();
    ASSERT_TRUE(manager->RegisterProvider(
        std::string{kConfiguredProviderName}, configured_provider, common::CryptoProviderType::SOFTWARE));
    ASSERT_TRUE(manager->Initialize());

    const auto module = cert::CertManagementModule::Create(nullptr, manager, m_config);

    ASSERT_NE(module, nullptr);
    EXPECT_NE(module->GetService(), nullptr);
}

TEST_F(CertModuleStartupTest, FailsWhenConfiguredParserProviderIsUnavailable)
{
    auto manager = std::make_shared<provider::ProviderManager>(config::ProviderInitConfig{});
    auto differently_named_provider = std::make_shared<openssl::OpenSSL>();
    ASSERT_TRUE(
        manager->RegisterProvider("ALT_PROVIDER", differently_named_provider, common::CryptoProviderType::SOFTWARE));
    ASSERT_TRUE(manager->Initialize());

    EXPECT_EQ(cert::CertManagementModule::Create(nullptr, manager, m_config), nullptr);
}
}  // namespace

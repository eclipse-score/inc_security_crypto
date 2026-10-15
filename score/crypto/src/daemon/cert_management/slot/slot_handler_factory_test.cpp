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

#include "score/crypto/src/daemon/cert_management/slot/slot_handler_factory.hpp"

#include "score/crypto/src/daemon/cert_management/cert_management_module.hpp"
#include "score/crypto/src/daemon/cert_management/slot/file_backed_slot_handler.hpp"
#include "score/crypto/src/daemon/config/inc/config.hpp"
#include "score/crypto/src/daemon/provider/provider_manager.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace
{
namespace cert = score::crypto::daemon::cert_management;
namespace provider = score::crypto::daemon::provider;
namespace cert_provider = score::crypto::daemon::provider::cert_management;
namespace common = score::crypto::daemon::common;
using Error = common::DaemonErrorCode;

class FakeParser final : public cert_provider::ICertParser
{
  public:
    score::crypto::Expected<cert::CertObject::Sptr, Error> ParseCertificate(const std::uint8_t*,
                                                                            std::size_t,
                                                                            score::crypto::FormatType) override
    {
        return score::crypto::make_unexpected(Error::kUnsupportedOperation);
    }

    score::crypto::Expected<std::vector<cert::CertObject::Sptr>, Error>
    ParseCertificates(const std::uint8_t*, std::size_t, score::crypto::FormatType) override
    {
        return score::crypto::make_unexpected(Error::kUnsupportedOperation);
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
        return score::crypto::make_unexpected(Error::kUnsupportedOperation);
    }
};

// Minimal ICertSlotHandler so a fake provider's GetCertSlotHandler() has a
// distinguishable, non-FileBackedSlotHandler instance to return.
class FakeCertSlotHandler final : public cert::ICertSlotHandler
{
  public:
    score::crypto::Expected<cert::CertObject::Sptr, Error> LoadCertificate(const cert::CertSlotConfig&) override
    {
        return score::crypto::make_unexpected(Error::kUnsupportedOperation);
    }

    score::crypto::Expected<score::crypto::CertificateSlotState, Error> GetSlotState(
        const cert::CertSlotConfig&) override
    {
        return score::crypto::CertificateSlotState::kEmpty;
    }

    score::crypto::Expected<score::crypto::CertificateSlotInfo, Error> GetSlotInfo(const cert::CertSlotConfig&) override
    {
        return score::crypto::CertificateSlotInfo{};
    }

    score::crypto::Expected<bool, Error> HasCrl(const cert::CertSlotConfig&) override
    {
        return false;
    }
};

// Tracks parser discovery at module creation and doubles as the named slot backend.
class FakeProvider final : public provider::IProvider
{
  public:
    bool Initialize(const provider::ProviderInitContext& ctx) override
    {
        m_id = ctx.numeric_id;
        m_name = ctx.name;
        m_initialized = true;
        return true;
    }

    void Shutdown() override
    {
        m_initialized = false;
    }

    [[nodiscard]] bool IsInitialized() const override
    {
        return m_initialized;
    }

    common::ProviderId GetProviderId() const override
    {
        return m_id;
    }

    const common::ProviderName& GetProviderName() const override
    {
        return m_name;
    }

    [[nodiscard]] common::ProviderCapability GetProviderCapabilities() override
    {
        return m_capabilities;
    }

    std::shared_ptr<cert_provider::ICertParser> GetCertParser() override
    {
        ++m_get_cert_parser_calls;
        return m_parser;
    }

    std::shared_ptr<cert::ICertSlotHandler> GetCertSlotHandler(
        const cert::CertSlotConfig&,
        std::shared_ptr<cert_provider::ICertParser> parser) override
    {
        m_last_parser_seen_by_slot_handler = parser;
        return m_slot_handler;
    }

    common::ProviderCapability m_capabilities{common::ProviderCapability::kNone};
    std::shared_ptr<cert_provider::ICertParser> m_parser;
    std::shared_ptr<cert::ICertSlotHandler> m_slot_handler;
    int m_get_cert_parser_calls{0};
    std::shared_ptr<cert_provider::ICertParser> m_last_parser_seen_by_slot_handler;

  private:
    bool m_initialized{false};
    common::ProviderId m_id{0};
    common::ProviderName m_name;
};

provider::ProviderManager::Sptr MakeProviderManager()
{
    return std::make_shared<provider::ProviderManager>(score::crypto::daemon::config::ProviderInitConfig{});
}

TEST(SlotHandlerFactoryTest, NullProviderManager_DefaultBackend_ReturnsFileBackedHandler)
{
    cert::SlotHandlerFactory factory{nullptr};
    cert::CertSlotConfig slot;
    slot.storage_backend = "DEFAULT";

    auto handler = factory(slot);

    ASSERT_NE(handler, nullptr);
    EXPECT_NE(std::dynamic_pointer_cast<cert::FileBackedSlotHandler>(handler), nullptr);
}

TEST(SlotHandlerFactoryTest, NullProviderManager_NamedBackend_ReturnsNull)
{
    cert::SlotHandlerFactory factory{nullptr};
    cert::CertSlotConfig slot;
    slot.storage_backend = "SOME_PROVIDER";

    EXPECT_EQ(factory(slot), nullptr);
}

TEST(SlotHandlerFactoryTest, NoCertManagementProvider_DefaultBackend_ReturnsFileBackedHandler)
{
    auto manager = MakeProviderManager();
    auto software_provider = std::make_shared<FakeProvider>();  // No capabilities advertised.
    ASSERT_TRUE(manager->RegisterProvider("OTHER", software_provider, common::CryptoProviderType::SOFTWARE));
    ASSERT_TRUE(manager->Initialize());

    cert::SlotHandlerFactory factory{manager};
    cert::CertSlotConfig slot;
    slot.storage_backend = "DEFAULT";

    auto handler = factory(slot);

    ASSERT_NE(handler, nullptr);
    EXPECT_NE(std::dynamic_pointer_cast<cert::FileBackedSlotHandler>(handler), nullptr);
}

TEST(SlotHandlerFactoryTest, UnknownNamedBackend_ReturnsNull)
{
    auto manager = MakeProviderManager();
    auto registered_provider = std::make_shared<FakeProvider>();
    ASSERT_TRUE(manager->RegisterProvider("OTHER", registered_provider, common::CryptoProviderType::SOFTWARE));
    ASSERT_TRUE(manager->Initialize());

    cert::SlotHandlerFactory factory{manager};
    cert::CertSlotConfig slot;
    slot.storage_backend = "UNKNOWN";

    EXPECT_EQ(factory(slot), nullptr);
}

TEST(CertManagementModuleTest, UsesConfiguredParserProvider)
{
    auto manager = MakeProviderManager();
    auto openssl_provider = std::make_shared<FakeProvider>();
    openssl_provider->m_capabilities = common::ProviderCapability::kCertManagement;
    openssl_provider->m_parser = std::make_shared<FakeParser>();
    ASSERT_TRUE(manager->RegisterProvider("OPENSSL", openssl_provider, common::CryptoProviderType::SOFTWARE));

    auto alternate_provider = std::make_shared<FakeProvider>();
    alternate_provider->m_capabilities = common::ProviderCapability::kCertManagement;
    alternate_provider->m_parser = std::make_shared<FakeParser>();
    ASSERT_TRUE(manager->RegisterProvider("ALT_PROVIDER", alternate_provider, common::CryptoProviderType::SOFTWARE));
    ASSERT_TRUE(manager->Initialize());

    score::crypto::daemon::config::CertificateConfig config;
    config.SetParserProviderName("ALT_PROVIDER");

    auto module = cert::CertManagementModule::Create(nullptr, manager, config);

    ASSERT_NE(module, nullptr);
    EXPECT_EQ(openssl_provider->m_get_cert_parser_calls, 0);
    EXPECT_EQ(alternate_provider->m_get_cert_parser_calls, 1);
}

TEST(SlotHandlerFactoryTest, InitializeDefaultsToSoftwareCapabilityProvider)
{
    auto manager = MakeProviderManager();
    auto hardware_provider = std::make_shared<FakeProvider>();
    hardware_provider->m_capabilities = common::ProviderCapability::kCertManagement;
    hardware_provider->m_parser = std::make_shared<FakeParser>();
    ASSERT_TRUE(manager->RegisterProvider("HARDWARE", hardware_provider, common::CryptoProviderType::HARDWARE));

    auto software_provider = std::make_shared<FakeProvider>();
    software_provider->m_capabilities = common::ProviderCapability::kCertManagement;
    software_provider->m_parser = std::make_shared<FakeParser>();
    ASSERT_TRUE(manager->RegisterProvider("SOFTWARE", software_provider, common::CryptoProviderType::SOFTWARE));
    ASSERT_TRUE(manager->Initialize());

    cert::SlotHandlerFactory factory{manager};
    const auto parser = factory.Initialize();

    ASSERT_TRUE(parser.has_value());
    EXPECT_EQ(software_provider->m_get_cert_parser_calls, 1);
    EXPECT_EQ(hardware_provider->m_get_cert_parser_calls, 0);
}

TEST(SlotHandlerFactoryTest, ConcurrentInitializationPublishesParserOnce)
{
    auto manager = MakeProviderManager();
    auto cert_provider = std::make_shared<FakeProvider>();
    cert_provider->m_capabilities = common::ProviderCapability::kCertManagement;
    cert_provider->m_parser = std::make_shared<FakeParser>();
    ASSERT_TRUE(manager->RegisterProvider("CERT_PROVIDER", cert_provider, common::CryptoProviderType::SOFTWARE));
    ASSERT_TRUE(manager->Initialize());

    cert::SlotHandlerFactory factory{manager};
    constexpr std::size_t kCallerCount = 8U;
    std::vector<std::thread> callers;
    std::vector<std::uint8_t> succeeded(kCallerCount, 0U);
    callers.reserve(kCallerCount);

    for (std::size_t index = 0U; index < kCallerCount; ++index)
    {
        callers.emplace_back([&factory, &succeeded, index]() {
            succeeded[index] = factory.Initialize().has_value() ? 1U : 0U;
        });
    }
    for (auto& caller : callers)
    {
        caller.join();
    }

    for (const auto result : succeeded)
    {
        EXPECT_EQ(result, 1U);
    }
    EXPECT_EQ(cert_provider->m_get_cert_parser_calls, 1);
}

TEST(SlotHandlerFactoryTest, RetriesParserResolutionAfterFailure)
{
    auto manager = MakeProviderManager();
    auto cert_provider = std::make_shared<FakeProvider>();
    cert_provider->m_capabilities = common::ProviderCapability::kCertManagement;
    ASSERT_TRUE(manager->RegisterProvider("CERT_PROVIDER", cert_provider, common::CryptoProviderType::SOFTWARE));
    ASSERT_TRUE(manager->Initialize());

    cert::SlotHandlerFactory factory{manager, "CERT_PROVIDER"};
    EXPECT_FALSE(factory.Initialize().has_value());

    cert_provider->m_parser = std::make_shared<FakeParser>();
    const auto parser = factory.Initialize();

    ASSERT_TRUE(parser.has_value());
    EXPECT_EQ(cert_provider->m_get_cert_parser_calls, 2);
}

TEST(CertManagementModuleTest, LeavesUnpinnedParserResolutionLazy)
{
    auto manager = MakeProviderManager();
    auto cert_provider = std::make_shared<FakeProvider>();
    cert_provider->m_capabilities = common::ProviderCapability::kCertManagement;
    cert_provider->m_parser = std::make_shared<FakeParser>();
    ASSERT_TRUE(manager->RegisterProvider("CERT_PROVIDER", cert_provider, common::CryptoProviderType::SOFTWARE));
    ASSERT_TRUE(manager->Initialize());

    const score::crypto::daemon::config::CertificateConfig config;
    const auto module = cert::CertManagementModule::Create(nullptr, manager, config);

    ASSERT_NE(module, nullptr);
    EXPECT_EQ(cert_provider->m_get_cert_parser_calls, 0);
}

TEST(CertManagementModuleTest, RejectsUnavailablePinnedParserProvider)
{
    score::crypto::daemon::config::CertificateConfig config;
    config.SetParserProviderName("MISSING");

    EXPECT_EQ(cert::CertManagementModule::Create(nullptr, MakeProviderManager(), config), nullptr);
}

TEST(CertManagementModuleTest, RejectsPinnedProviderWithoutCertManagementCapability)
{
    auto manager = MakeProviderManager();
    auto provider_without_cert_capability = std::make_shared<FakeProvider>();
    provider_without_cert_capability->m_parser = std::make_shared<FakeParser>();
    ASSERT_TRUE(manager->RegisterProvider(
        "NO_CERT_CAPABILITY", provider_without_cert_capability, common::CryptoProviderType::SOFTWARE));
    ASSERT_TRUE(manager->Initialize());

    score::crypto::daemon::config::CertificateConfig config;
    config.SetParserProviderName("NO_CERT_CAPABILITY");

    EXPECT_EQ(cert::CertManagementModule::Create(nullptr, manager, config), nullptr);
    EXPECT_EQ(provider_without_cert_capability->m_get_cert_parser_calls, 0);
}

TEST(CertManagementModuleTest, RejectsPinnedProviderWithoutParser)
{
    auto manager = MakeProviderManager();
    auto provider_without_parser = std::make_shared<FakeProvider>();
    provider_without_parser->m_capabilities = common::ProviderCapability::kCertManagement;
    ASSERT_TRUE(manager->RegisterProvider("NO_PARSER", provider_without_parser, common::CryptoProviderType::SOFTWARE));
    ASSERT_TRUE(manager->Initialize());

    score::crypto::daemon::config::CertificateConfig config;
    config.SetParserProviderName("NO_PARSER");

    EXPECT_EQ(cert::CertManagementModule::Create(nullptr, manager, config), nullptr);
    EXPECT_EQ(provider_without_parser->m_get_cert_parser_calls, 1);
}

TEST(CertManagementModuleTest, AllowsStartupWithoutParserWhenNoProviderIsPinned)
{
    const score::crypto::daemon::config::CertificateConfig config;

    EXPECT_NE(cert::CertManagementModule::Create(nullptr, nullptr, config), nullptr);
}

TEST(SlotHandlerFactoryTest, NamedBackend_ReceivesCanonicalParser)
{
    auto manager = MakeProviderManager();

    auto parser = std::make_shared<FakeParser>();
    auto cert_provider = std::make_shared<FakeProvider>();
    cert_provider->m_capabilities = common::ProviderCapability::kCertManagement;
    cert_provider->m_parser = parser;
    ASSERT_TRUE(manager->RegisterProvider("CERT_PROVIDER", cert_provider, common::CryptoProviderType::SOFTWARE));

    auto hw_provider = std::make_shared<FakeProvider>();
    auto fake_handler = std::make_shared<FakeCertSlotHandler>();
    hw_provider->m_slot_handler = fake_handler;
    ASSERT_TRUE(manager->RegisterProvider("HW", hw_provider, common::CryptoProviderType::HARDWARE));

    ASSERT_TRUE(manager->Initialize());

    cert::SlotHandlerFactory factory{manager};
    cert::CertSlotConfig slot;
    slot.storage_backend = "HW";

    auto handler = factory(slot);

    EXPECT_EQ(handler, fake_handler);
    EXPECT_EQ(hw_provider->m_last_parser_seen_by_slot_handler, parser);
    EXPECT_EQ(cert_provider->m_get_cert_parser_calls, 1);
}

}  // namespace

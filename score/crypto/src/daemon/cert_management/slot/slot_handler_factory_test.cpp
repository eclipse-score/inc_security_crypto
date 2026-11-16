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

#include "score/crypto/src/daemon/cert_management/slot/file_backed_slot_handler.hpp"
#include "score/crypto/src/daemon/provider/provider_manager.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <string>
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

// Advertises kCertManagement (so SlotHandlerFactory can resolve a parser from it) and
// tracks GetCertParser() invocations to verify SlotHandlerFactory's caching behavior.
// Also doubles as the "named backend" provider via GetCertSlotHandler().
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

TEST(SlotHandlerFactoryTest, ExpiredProviderManager_DefaultBackend_StillReturnsFileBackedHandler)
{
    cert::SlotHandlerFactory factory{[]() {
        // ProviderManager is destroyed before the factory is ever invoked — the
        // factory's weak_ptr must not revive it.
        auto manager = MakeProviderManager();
        return manager;
    }()};

    cert::CertSlotConfig slot;
    slot.storage_backend = "DEFAULT";

    auto handler = factory(slot);

    ASSERT_NE(handler, nullptr);
    EXPECT_NE(std::dynamic_pointer_cast<cert::FileBackedSlotHandler>(handler), nullptr);
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

TEST(SlotHandlerFactoryTest, ResolvedParser_IsCachedAcrossCalls)
{
    auto manager = MakeProviderManager();
    auto cert_mgmt_provider = std::make_shared<FakeProvider>();
    cert_mgmt_provider->m_capabilities = common::ProviderCapability::kCertManagement;
    cert_mgmt_provider->m_parser = std::make_shared<FakeParser>();
    ASSERT_TRUE(manager->RegisterProvider("SOFT", cert_mgmt_provider, common::CryptoProviderType::SOFTWARE));
    ASSERT_TRUE(manager->Initialize());

    cert::SlotHandlerFactory factory{manager};
    cert::CertSlotConfig slot;
    slot.storage_backend = "DEFAULT";

    auto handler_one = factory(slot);
    auto handler_two = factory(slot);

    ASSERT_NE(handler_one, nullptr);
    ASSERT_NE(handler_two, nullptr);
    EXPECT_EQ(cert_mgmt_provider->m_get_cert_parser_calls, 1);
}

TEST(SlotHandlerFactoryTest, NamedBackend_DelegatesToNamedProviderWithResolvedParser)
{
    auto manager = MakeProviderManager();

    auto cert_mgmt_provider = std::make_shared<FakeProvider>();
    cert_mgmt_provider->m_capabilities = common::ProviderCapability::kCertManagement;
    auto parser = std::make_shared<FakeParser>();
    cert_mgmt_provider->m_parser = parser;
    ASSERT_TRUE(manager->RegisterProvider("SOFT", cert_mgmt_provider, common::CryptoProviderType::SOFTWARE));

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
}

}  // namespace

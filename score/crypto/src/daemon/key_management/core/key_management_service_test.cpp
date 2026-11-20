/*******************************************************************************
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
 *******************************************************************************/

#include "score/crypto/src/daemon/key_management/core/key_management_service.hpp"

#include "score/crypto/src/api/types/key.hpp"
#include "score/crypto/src/daemon/common/algorithm_catalog.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/config/inc/config.hpp"
#include "score/crypto/src/daemon/data_manager/data_manager.hpp"
#include "score/crypto/src/daemon/data_manager/data_node_accessor.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/i_key_handler.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/i_key_slot_handler.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_slot_config.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_types.hpp"
#include "score/crypto/src/daemon/key_management/nodes/key_slot_data_node.hpp"
#include "score/crypto/src/daemon/key_management/slot/slot_registry.hpp"
#include "score/crypto/src/daemon/provider/i_provider.hpp"
#include "score/crypto/src/daemon/provider/provider_manager.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace
{

namespace common = score::crypto::daemon::common;
namespace config = score::crypto::daemon::config;
namespace data_manager = score::crypto::daemon::data_manager;
namespace km = score::crypto::daemon::key_management;
namespace provider = score::crypto::daemon::provider;

constexpr std::uint64_t kClient = 7U;
constexpr std::string_view kProviderName{"STUB"};
constexpr std::string_view kAlgorithmName{"AES-256-CMAC"};
constexpr std::size_t kKeyBytes = 32U;       // AES-256
constexpr std::size_t kShortKeyBytes = 16U;  // AES-128 material offered for an AES-256 slot

/// Key handler whose metadata and material size are fixed by the test.
class StubKeyHandler final : public km::IKeyHandler
{
  public:
    StubKeyHandler(const km::ProviderKeyHandle& handle, common::ProviderId provider_id)
        : m_handle{handle}, m_provider_id{provider_id}
    {
    }

    const km::ProviderKeyHandle& GetHandle() const noexcept override
    {
        return m_handle;
    }

    common::ProviderId GetProviderId() const noexcept override
    {
        return m_provider_id;
    }

    score::crypto::Expected<std::monostate, common::DaemonErrorCode> Release() override
    {
        return std::monostate{};
    }

    score::crypto::Expected<km::SecureKeyBytes, common::DaemonErrorCode> Export() const override
    {
        return score::crypto::make_unexpected(common::DaemonErrorCode::kKeyNotExportable);
    }

  private:
    km::ProviderKeyHandle m_handle;
    common::ProviderId m_provider_id;
};

/// Slot handler that produces a key of the configured size on each load and counts the loads.
class StubSlotHandler final : public km::IKeySlotHandler
{
  public:
    void SetProviderId(common::ProviderId provider_id) noexcept
    {
        m_provider_id = provider_id;
    }

    void SetKeyBytes(std::size_t key_bytes) noexcept
    {
        m_key_bytes = key_bytes;
    }

    int LoadCalls() const noexcept
    {
        return m_load_calls;
    }

    score::crypto::Expected<km::IKeyHandler::Sptr, common::DaemonErrorCode> LoadKey(
        const km::KeySlotConfig& slot) override
    {
        ++m_load_calls;
        km::ProviderKeyHandle handle{};
        handle.provider_id = m_provider_id;
        handle.permissions = score::crypto::KeyOperationPermission::kMac;
        handle.algorithm = *score::crypto::GetAlgorithmDescriptor(slot.algorithm);
        handle.key_size = m_key_bytes;
        return km::IKeyHandler::Sptr{std::make_shared<StubKeyHandler>(handle, m_provider_id)};
    }

    score::crypto::Expected<score::crypto::KeySlotState, common::DaemonErrorCode> GetSlotState(
        const km::KeySlotConfig& /*slot*/) override
    {
        return score::crypto::make_unexpected(common::DaemonErrorCode::kUnsupportedOperation);
    }

    score::crypto::Expected<score::crypto::KeySlotInfo, common::DaemonErrorCode> GetSlotInfo(
        const km::KeySlotConfig& /*slot*/) override
    {
        return score::crypto::make_unexpected(common::DaemonErrorCode::kUnsupportedOperation);
    }

  private:
    common::ProviderId m_provider_id{common::kInvalidProviderId};
    std::size_t m_key_bytes{kKeyBytes};
    int m_load_calls{0};
};

/// Provider that serves one slot handler and reports the id the provider manager assigned to it.
class StubProvider final : public provider::IProvider
{
  public:
    explicit StubProvider(std::shared_ptr<StubSlotHandler> slot_handler) : m_slot_handler{std::move(slot_handler)} {}

    bool Initialize(const provider::ProviderInitContext& ctx) override
    {
        m_provider_id = ctx.numeric_id;
        m_slot_handler->SetProviderId(m_provider_id);
        m_initialized = true;
        return true;
    }

    void Shutdown() override
    {
        m_initialized = false;
    }

    bool IsInitialized() const override
    {
        return m_initialized;
    }

    common::ProviderId GetProviderId() const override
    {
        return m_provider_id;
    }

    const common::ProviderName& GetProviderName() const override
    {
        return m_name;
    }

    std::shared_ptr<km::IKeySlotHandler> GetKeySlotHandler(const km::KeySlotConfig& /*config*/) override
    {
        return m_slot_handler;
    }

  private:
    std::shared_ptr<StubSlotHandler> m_slot_handler;
    common::ProviderId m_provider_id{common::kInvalidProviderId};
    common::ProviderName m_name{std::string{kProviderName}};
    bool m_initialized{false};
};

class BindAndAuthorizeTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        m_data_manager = std::make_shared<data_manager::DataManager>();
        m_slot_registry = std::make_shared<km::SlotRegistry>();
        m_slot_handler = std::make_shared<StubSlotHandler>();
        m_provider = std::make_shared<StubProvider>(m_slot_handler);

        m_provider_manager = std::make_shared<provider::ProviderManager>(config::ProviderInitConfig{});
        ASSERT_TRUE(m_provider_manager->RegisterProvider(
            std::string{kProviderName}, m_provider, common::CryptoProviderType::SOFTWARE));
        ASSERT_TRUE(m_provider_manager->Initialize());

        m_kms = std::make_shared<km::KeyManagementService>(m_data_manager, m_provider_manager, m_slot_registry);

        const auto connection =
            m_data_manager->addNode(kClient, std::make_shared<data_manager::DataNode>(/*exclusiveAccess=*/false));
        ASSERT_TRUE(connection.has_value());
        m_connection_node = connection.value();

        const auto context = m_data_manager->addChildNode(
            kClient, m_connection_node, std::make_shared<data_manager::DataNode>(/*exclusiveAccess=*/false));
        ASSERT_TRUE(context.has_value());
        m_context_node = context.value();
    }

    void TearDown() override
    {
        // A key node unregisters its key from the service's registry when it is destroyed, so the registries must
        // outlive every key node. The fixture shares the data manager with the service; dropping the fixture's
        // reference first leaves the service as the last owner, and it destroys the data manager before its
        // registries.
        m_data_manager.reset();
    }

    /// Adds a key slot that permits @p allowed operations and returns its node id.
    score::crypto::Expected<data_manager::DataNodeId, common::DaemonErrorCode> AddSlot(
        score::crypto::KeyOperationPermission allowed)
    {
        km::KeySlotConfig config{};
        config.slot_name = "slot";
        config.algorithm = std::string{kAlgorithmName};
        config.provider_names = {std::string{kProviderName}};
        config.allowed_operations = allowed;

        const auto handle = m_slot_registry->RegisterSlot(config);
        m_slot_registry->ResolveProviderIds(*m_provider_manager);
        return m_data_manager->addNode(kClient, std::make_shared<km::KeySlotDataNode>(handle, m_slot_registry));
    }

    /// Registers an already loaded key, and returns the id of its key node.
    score::crypto::Expected<data_manager::DataNodeId, common::DaemonErrorCode> RegisterLoadedKey(
        score::crypto::KeyOperationPermission permissions,
        std::size_t key_bytes)
    {
        km::ProviderKeyHandle handle{};
        handle.provider_id = m_provider->GetProviderId();
        handle.permissions = permissions;
        handle.algorithm = *score::crypto::GetAlgorithmDescriptor(kAlgorithmName);
        handle.key_size = key_bytes;

        km::KeyRegistrationParams params{};
        params.client_id = kClient;
        params.parent_id = m_connection_node;
        params.provider_id = m_provider->GetProviderId();

        const auto result =
            m_kms->RegisterKeyMaterial(params, std::make_shared<StubKeyHandler>(handle, m_provider->GetProviderId()));
        if (!result.has_value())
        {
            return score::crypto::make_unexpected(result.error());
        }
        return result.value().node_id;
    }

    /// A request that asks for a CMAC permission on @p key_node_id, bound to the test context.
    km::KeyBindRequest Request(data_manager::DataNodeId key_node_id) const
    {
        km::KeyBindRequest request{};
        request.client_id = kClient;
        request.context_node_id = m_context_node;
        request.key_node_id = key_node_id;
        request.provider_id = m_provider->GetProviderId();
        request.permission = score::crypto::KeyOperationPermission::kMac;
        request.algorithm = score::crypto::GetAlgorithmDescriptor(kAlgorithmName);
        return request;
    }

    std::shared_ptr<data_manager::DataManager> m_data_manager;
    std::shared_ptr<km::SlotRegistry> m_slot_registry;
    std::shared_ptr<StubSlotHandler> m_slot_handler;
    std::shared_ptr<StubProvider> m_provider;
    std::shared_ptr<provider::ProviderManager> m_provider_manager;
    std::shared_ptr<km::KeyManagementService> m_kms;
    data_manager::DataNodeId m_connection_node{0U};
    data_manager::DataNodeId m_context_node{0U};
};

TEST_F(BindAndAuthorizeTest, AbsentPermissionIsRefusedBeforeTheKeyIsLoaded)
{
    const auto slot = AddSlot(score::crypto::KeyOperationPermission::kMac);
    ASSERT_TRUE(slot.has_value());
    auto request = Request(slot.value());
    request.permission = std::nullopt;

    const auto result = m_kms->BindAndAuthorize(request);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kKeyOperationNotPermitted);
    EXPECT_EQ(m_slot_handler->LoadCalls(), 0);
}

TEST_F(BindAndAuthorizeTest, UnknownKeyNodeIsRefused)
{
    const auto result = m_kms->BindAndAuthorize(Request(424242U));

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kInvalidArgument);
}

TEST_F(BindAndAuthorizeTest, KeyWithoutTheRequiredPermissionIsRefusedBeforeTheKeyIsLoaded)
{
    const auto slot = AddSlot(score::crypto::KeyOperationPermission::kEncrypt);
    ASSERT_TRUE(slot.has_value());

    const auto result = m_kms->BindAndAuthorize(Request(slot.value()));

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kKeyOperationNotPermitted);
    EXPECT_EQ(m_slot_handler->LoadCalls(), 0);
}

TEST_F(BindAndAuthorizeTest, MissingAlgorithmIsRefusedBeforeTheKeyIsLoaded)
{
    const auto slot = AddSlot(score::crypto::KeyOperationPermission::kMac);
    ASSERT_TRUE(slot.has_value());
    auto request = Request(slot.value());
    request.algorithm = std::nullopt;

    const auto result = m_kms->BindAndAuthorize(request);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kIncompatibleKeyType);
    EXPECT_EQ(m_slot_handler->LoadCalls(), 0);
}

TEST_F(BindAndAuthorizeTest, LoadedCompatibleKeyIsBoundUnderTheContext)
{
    const auto key = RegisterLoadedKey(score::crypto::KeyOperationPermission::kMac, kKeyBytes);
    ASSERT_TRUE(key.has_value());

    const auto result = m_kms->BindAndAuthorize(Request(key.value()));

    ASSERT_TRUE(result.has_value());
    // The bind creates a new key node under the context; the caller's key node is not returned.
    EXPECT_NE(result.value().resolved_node_id, key.value());
    EXPECT_TRUE(m_data_manager->getNodeAccessor(kClient, result.value().resolved_node_id).has_value());
    EXPECT_EQ(result.value().key_handler->GetHandle().key_size, kKeyBytes);
    EXPECT_EQ(m_slot_handler->LoadCalls(), 0);
}

TEST_F(BindAndAuthorizeTest, CompatibleSlotKeyIsLoadedOnceAndBound)
{
    m_slot_handler->SetKeyBytes(kKeyBytes);
    const auto slot = AddSlot(score::crypto::KeyOperationPermission::kMac);
    ASSERT_TRUE(slot.has_value());

    const auto result = m_kms->BindAndAuthorize(Request(slot.value()));

    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result.value().resolved_node_id, slot.value());
    EXPECT_TRUE(m_data_manager->getNodeAccessor(kClient, result.value().resolved_node_id).has_value());
    EXPECT_EQ(m_slot_handler->LoadCalls(), 1);
}

TEST_F(BindAndAuthorizeTest, IncompatibleLoadedSlotKeyIsRefusedAndReleasedAfterTheFailure)
{
    m_slot_handler->SetKeyBytes(kShortKeyBytes);
    const auto slot = AddSlot(score::crypto::KeyOperationPermission::kMac);
    ASSERT_TRUE(slot.has_value());

    const auto first = m_kms->BindAndAuthorize(Request(slot.value()));
    ASSERT_FALSE(first.has_value());
    EXPECT_EQ(first.error(), common::DaemonErrorCode::kIncompatibleKeyType);
    EXPECT_EQ(m_slot_handler->LoadCalls(), 1);

    // The failed bind removed its key node, so the key is no longer held and the slot is loaded again.
    const auto second = m_kms->BindAndAuthorize(Request(slot.value()));
    ASSERT_FALSE(second.has_value());
    EXPECT_EQ(second.error(), common::DaemonErrorCode::kIncompatibleKeyType);
    EXPECT_EQ(m_slot_handler->LoadCalls(), 2);
}

}  // namespace

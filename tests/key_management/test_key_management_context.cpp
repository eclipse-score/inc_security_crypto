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

/// @file test_key_management_context.cpp
/// @brief Integration tests for OpenSslKeyManagementHandler + KeyManagementService.
///
/// Uses real DataManager, real SlotRegistry (built-in slot definitions from
/// binary config configuration), real
/// OpenSslKeyManagementHandler and FileBackedSlotHandler. Exercises the full
/// handler dispatch flow without mocks.

#include "score/crypto/daemon/common/actors.hpp"
#include "score/crypto/daemon/config/src/flatbuffer_config_parser.hpp"
#include "score/crypto/daemon/data_manager/data_manager.hpp"
#include "score/crypto/daemon/key_management/core/key_management_service.hpp"
#include "score/crypto/daemon/key_management/interfaces/key_management_operations.hpp"
#include "score/crypto/daemon/key_management/nodes/key_slot_data_node.hpp"
#include "score/crypto/daemon/key_management/slot/config_driven_slot_catalog.hpp"
#include "score/crypto/daemon/key_management/slot/file_backed_slot_handler.hpp"
#include "score/crypto/daemon/key_management/slot/slot_registry.hpp"
#include "score/crypto/daemon/provider/executors/key_mgmt_executor.hpp"
#include "score/crypto/daemon/provider/handler/handler_init_params.hpp"
#include "score/crypto/daemon/provider/score_provider/openssl/key_management/openssl_key_factory.hpp"
#include "score/crypto/daemon/provider/score_provider/openssl/operations/key_management/openssl_key_management_handler.hpp"
#include "score/mw/crypto/api/common/error_domain.hpp"
#include "score/mw/crypto/api/common/types.hpp"

#include <gtest/gtest.h>
#include <cstdint>
#include <memory>

namespace km = score::crypto::daemon::key_management;
namespace dm = score::crypto::daemon::data_manager;
namespace ossl = score::crypto::daemon::provider::openssl;
namespace handler = score::crypto::daemon::provider::handler;
namespace handler_ns = score::crypto::daemon::provider::score_provider::openssl::handler;
namespace common = score::crypto::daemon::common;
namespace config = score::crypto::daemon::config;
namespace crypto_executor = score::crypto::daemon::provider::crypto_executor;

// ---------------------------------------------------------------------------
// Test fixture
// ---------------------------------------------------------------------------
class KeyManagementHandlerTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        m_data_manager = std::make_shared<dm::DataManager>();
        m_km_handler = std::make_shared<ossl::OpenSslKeyFactory>(kProviderId);
        m_slot_handler = std::make_shared<km::FileBackedSlotHandler>(m_km_handler);
        m_slot_registry = std::make_shared<km::SlotRegistry>();

        // Load test slot definitions from test config
        config::KeyConfig test_config{};
        auto result = config::FlatBufferConfigParser::ParseFromFile(
            "tests/key_management/config/key_management_test_config.bin", test_config);
        ASSERT_TRUE(result.has_value()) << "Failed to parse test config";

        // Use ConfigDrivenSlotCatalog to properly convert and register slots
        km::ConfigDrivenSlotCatalog catalog{test_config};
        catalog.Load(*m_slot_registry);

        // KeyManagementService needs a DataManager, optional ProviderManager, and config.
        m_service =
            std::make_shared<km::KeyManagementService>(m_data_manager, nullptr /*provider_manager*/, m_slot_registry);

        // Register a placeholder parent (context) node so we have a valid parent_id.
        auto parent_node = std::make_shared<dm::DataNode>(/*exclusiveAccess=*/false);
        auto reg = m_data_manager->addNode(kAllowedClient, parent_node);
        ASSERT_TRUE(reg.has_value());
        m_parent_id = reg.value();

        // Build the handler: factory creates executor and injects into handler
        auto executor =
            std::make_unique<crypto_executor::KeyManagementExecutor>(m_km_handler, m_slot_handler, m_service);
        m_handler = std::make_shared<handler_ns::OpenSslKeyManagementHandler>(std::move(executor));

        // Initialize handler context with client identity and assigned node IDs
        handler::InitializationParams init_params{.client_id = kAllowedClient,
                                                  .context_node_id = m_parent_id,
                                                  .provider_id = kProviderId,
                                                  .key_node_id = 0U,
                                                  .bound_key_handler = nullptr};
        auto init_result = m_handler->InitializeContext(init_params);
        ASSERT_TRUE(init_result.has_value()) << "InitializeContext failed";
    }

    /// Helper: clear parameters. Context (client_id, context_node_id) comes from InitializeContext().
    void SetStandardParams(common::RequestParameters& params) const
    {
        params.clear();
        // Do NOT include context_id, client_id, or parent_id here
        // These are set via InitializeContext() on the handler
    }

    /// Helper: resolve a slot and register it as a KeySlotDataNode.
    dm::DataNodeId ResolveSlotToDataNode(const std::string& slot_name, dm::ClientId client_id)
    {
        auto handle = m_slot_registry->ResolveSlot(slot_name, client_id);
        if (!handle.has_value())
        {
            return 0U;
        }
        auto slot_node = std::make_shared<km::KeySlotDataNode>(handle.value(), m_slot_registry);
        auto node_id = m_data_manager->addNode(client_id, std::move(slot_node));
        return node_id.has_value() ? node_id.value() : 0U;
    }

    /// Client with UID=1000 (allowed) in upper 32 bits, PID=42 in lower 32 bits
    static constexpr dm::ClientId kAllowedClient = (1000ULL << 32) | 42ULL;
    /// Client with UID=9999 (not in allowed_uids list) in upper 32 bits
    static constexpr dm::ClientId kDeniedClient = (9999ULL << 32) | 42ULL;
    static constexpr common::ProviderId kProviderId = 0;  // OPENSSL provider (registered first)

    dm::DataManager::Sptr m_data_manager;
    km::SlotRegistry::Sptr m_slot_registry;
    km::IKeyFactory::Sptr m_km_handler;
    km::IKeySlotHandler::Sptr m_slot_handler;
    km::KeyManagementService::Sptr m_service;
    std::shared_ptr<handler_ns::OpenSslKeyManagementHandler> m_handler;
    dm::DataNodeId m_parent_id{0U};
};

// ============================================================================
// GetKeySlotInfo tests (via Execute with KEY_SLOT_INFO)
// ============================================================================

TEST_F(KeyManagementHandlerTest, GetKeySlotInfo_KnownSlot_ReturnsState)
{
    const auto slot_node_id = ResolveSlotToDataNode("test/hmac-sha256", kAllowedClient);
    ASSERT_NE(slot_node_id, 0U);

    common::RequestParameters params;
    SetStandardParams(params);
    params.push_back(static_cast<std::uint64_t>(slot_node_id));

    auto result = m_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_SLOT_INFO}, params);
    ASSERT_TRUE(result.has_value());
    ASSERT_FALSE(result.value().empty());
}

TEST_F(KeyManagementHandlerTest, GetKeySlotInfo_SecondSlot_ReturnsState)
{
    const auto slot_node_id = ResolveSlotToDataNode("test/aes-256-cmac", kAllowedClient);
    ASSERT_NE(slot_node_id, 0U);

    common::RequestParameters params;
    SetStandardParams(params);
    params.push_back(static_cast<std::uint64_t>(slot_node_id));

    auto result = m_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_SLOT_INFO}, params);
    ASSERT_TRUE(result.has_value());
}

TEST_F(KeyManagementHandlerTest, GetKeySlotInfo_InvalidSlotNodeId_ReturnsError)
{
    common::RequestParameters params;
    SetStandardParams(params);
    params.push_back(static_cast<std::uint64_t>(0xFFFFFFFFU));  // invalid

    auto result = m_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_SLOT_INFO}, params);
    ASSERT_FALSE(result.has_value());
}

TEST_F(KeyManagementHandlerTest, GetKeySlotInfo_DeniedClient_ReturnsError)
{
    // A client whose UID is NOT in the slot's allowed_uids must be denied access.
    // We verify this at the SlotRegistry::ResolveSlot level (where access control
    // is enforced) rather than through the handler, because the handler's context
    // is fixed at InitializeContext time.

    // 1. Ensure the slot exists and can be resolved by the allowed client.
    const auto allowed_slot = m_slot_registry->ResolveSlot("test/hmac-sha256", kAllowedClient);
    ASSERT_TRUE(allowed_slot.has_value()) << "Slot must be resolvable by allowed client";

    // 2. The denied client (UID 9999) must fail resolution.
    const auto denied_slot = m_slot_registry->ResolveSlot("test/hmac-sha256", kDeniedClient);
    ASSERT_FALSE(denied_slot.has_value()) << "Denied client must not resolve the slot";

    // 3. Additionally, build a handler initialized as kDeniedClient and verify
    //    that KEY_SLOT_INFO returns an error when no valid slot node can be provided.
    auto denied_executor =
        std::make_unique<crypto_executor::KeyManagementExecutor>(m_km_handler, m_slot_handler, m_service);
    auto denied_handler = std::make_shared<handler_ns::OpenSslKeyManagementHandler>(std::move(denied_executor));

    auto denied_parent_node = std::make_shared<dm::DataNode>(/*exclusiveAccess=*/false);
    auto denied_parent = m_data_manager->addNode(kDeniedClient, denied_parent_node);
    ASSERT_TRUE(denied_parent.has_value());

    handler::InitializationParams denied_init{.client_id = kDeniedClient,
                                              .context_node_id = denied_parent.value(),
                                              .provider_id = kProviderId,
                                              .key_node_id = 0U,
                                              .bound_key_handler = nullptr};
    auto init_result = denied_handler->InitializeContext(denied_init);
    ASSERT_TRUE(init_result.has_value()) << "Handler init must succeed (denial is at slot level)";

    // Denied client has no valid slot data node, so an invalid id yields an error.
    common::RequestParameters params;
    params.push_back(static_cast<std::uint64_t>(0xFFFFFFFFU));

    auto result = denied_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_SLOT_INFO}, params);
    ASSERT_FALSE(result.has_value()) << "Denied client must not access slot info";
}

// ============================================================================
// GenerateKey tests (ephemeral keys, via Execute with KEY_GENERATE)
// ============================================================================

TEST_F(KeyManagementHandlerTest, GenerateKey_HmacSha256_ReturnsNodeId)
{
    common::RequestParameters params;
    SetStandardParams(params);
    const std::string algo = "HMAC-SHA256";
    params.push_back(std::string_view(algo));
    params.push_back(static_cast<std::uint64_t>(score::mw::crypto::KeyOperationPermission::kMac));

    auto result = m_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_GENERATE}, params);
    ASSERT_TRUE(result.has_value());
    ASSERT_FALSE(result.value().empty());
    EXPECT_NE(std::get<std::uint64_t>(result.value()[0]), 0U);
}

TEST_F(KeyManagementHandlerTest, GenerateKey_UnknownAlgorithm_ReturnsError)
{
    common::RequestParameters params;
    SetStandardParams(params);
    const std::string algo = "UNKNOWN-ALGO";
    params.push_back(std::string_view(algo));
    params.push_back(static_cast<std::uint64_t>(score::mw::crypto::KeyOperationPermission::kMac));

    auto result = m_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_GENERATE}, params);
    ASSERT_FALSE(result.has_value());
}

// ============================================================================
// Execute dispatch tests
// ============================================================================

TEST_F(KeyManagementHandlerTest, Execute_UnknownAction_ReturnsError)
{
    common::RequestParameters params;
    SetStandardParams(params);

    auto result = m_handler->Execute({score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, 0xFFFFU}, params);
    ASSERT_FALSE(result.has_value());
}

// ============================================================================
// ReleaseKey tests
// ============================================================================

TEST_F(KeyManagementHandlerTest, GenerateAndRelease_EphemeralKey_FullLifecycle)
{
    // Generate
    common::RequestParameters gen_params;
    SetStandardParams(gen_params);
    const std::string algo = "HMAC-SHA256";
    gen_params.push_back(std::string_view(algo));
    gen_params.push_back(static_cast<std::uint64_t>(score::mw::crypto::KeyOperationPermission::kMac));

    auto gen = m_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_GENERATE}, gen_params);
    ASSERT_TRUE(gen.has_value());
    const auto key_node_id = std::get<std::uint64_t>(gen.value()[0]);

    // Release
    common::RequestParameters rel_params;
    SetStandardParams(rel_params);
    rel_params.push_back(static_cast<std::uint64_t>(key_node_id));

    auto release = m_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_RELEASE}, rel_params);
    ASSERT_TRUE(release.has_value());
}

TEST_F(KeyManagementHandlerTest, ReleaseKey_InvalidNodeId_ReturnsError)
{
    common::RequestParameters rel_params;
    SetStandardParams(rel_params);
    rel_params.push_back(static_cast<std::uint64_t>(0xDEADBEEFU));

    auto result = m_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_RELEASE}, rel_params);
    ASSERT_FALSE(result.has_value());
}

// ============================================================================
// Multiple ephemeral keys -- independent lifecycle
// ============================================================================

TEST_F(KeyManagementHandlerTest, MultipleEphemeralKeys_IndependentLifecycle)
{
    const std::string algo1 = "HMAC-SHA256";
    const std::string algo2 = "HMAC-SHA512";

    // Generate key 1
    common::RequestParameters gen1_params;
    SetStandardParams(gen1_params);
    gen1_params.push_back(std::string_view(algo1));
    gen1_params.push_back(static_cast<std::uint64_t>(score::mw::crypto::KeyOperationPermission::kMac));

    auto g1 = m_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_GENERATE}, gen1_params);
    ASSERT_TRUE(g1.has_value());
    const auto g1_id = std::get<std::uint64_t>(g1.value()[0]);

    // Generate key 2
    common::RequestParameters gen2_params;
    SetStandardParams(gen2_params);
    gen2_params.push_back(std::string_view(algo2));
    gen2_params.push_back(static_cast<std::uint64_t>(score::mw::crypto::KeyOperationPermission::kMac));

    auto g2 = m_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_GENERATE}, gen2_params);
    ASSERT_TRUE(g2.has_value());
    const auto g2_id = std::get<std::uint64_t>(g2.value()[0]);

    EXPECT_NE(g1_id, g2_id);

    // Release in reverse order
    common::RequestParameters rel2_params;
    SetStandardParams(rel2_params);
    rel2_params.push_back(g2_id);
    auto r2 = m_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_RELEASE}, rel2_params);
    EXPECT_TRUE(r2.has_value());

    common::RequestParameters rel1_params;
    SetStandardParams(rel1_params);
    rel1_params.push_back(g1_id);
    auto r1 = m_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_RELEASE}, rel1_params);
    EXPECT_TRUE(r1.has_value());
}

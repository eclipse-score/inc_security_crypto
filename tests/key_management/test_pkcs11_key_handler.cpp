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

/// @file test_pkcs11_key_handler.cpp
/// @brief Integration tests for Pkcs11KeyManagementHandler and Pkcs11KeySlotHandler
///        using a live SoftHSM2 token.
///
/// ### Test coverage
///  1. GenerateKey_AES256_ReturnsHandle          — KEY_GENERATE via Execute()
///  2. ImportAndRelease_HmacSha256_FullLifecycle — KEY_GENERATE (simulated) + KEY_RELEASE
///  3. LoadKey_ByLabel_ReturnsHandle             — KEY_LOAD via Execute()
///  4. LoadKey_ExtractableKey_ReturnsNativeHandle — token object load
///
/// All tests share the SofthsmTestFixture (SetUp / TearDown initialises a fresh
/// in-memory SoftHSM2 token per test).

#include "tests/softhsm/softhsm_test_fixture.hpp"

#include "score/crypto/daemon/common/actors.hpp"
#include "score/crypto/daemon/data_manager/data_manager.hpp"
#include "score/crypto/daemon/key_management/core/key_management_service.hpp"
#include "score/crypto/daemon/key_management/interfaces/i_key_slot_handler.hpp"
#include "score/crypto/daemon/key_management/interfaces/key_management_operations.hpp"
#include "score/crypto/daemon/key_management/interfaces/key_slot_config.hpp"
#include "score/crypto/daemon/key_management/nodes/key_slot_data_node.hpp"
#include "score/crypto/daemon/key_management/slot/slot_registry.hpp"
#include "score/crypto/daemon/provider/pkcs11/key_management/pkcs11_key_slot_handler.hpp"
#include "score/crypto/daemon/provider/pkcs11/operations/key_management/pkcs11_key_management_handler.hpp"
#include "score/crypto/daemon/provider/pkcs11/pkcs11_module.hpp"
#include "score/crypto/daemon/provider/pkcs11/pkcs11_provider.hpp"

#include <gtest/gtest.h>
#include <pkcs11.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Namespace aliases
// ---------------------------------------------------------------------------
namespace pkcs11_ns = score::crypto::daemon::provider::pkcs11;
namespace km = score::crypto::daemon::key_management;
namespace dm = score::crypto::daemon::data_manager;
namespace common = score::crypto::daemon::common;
namespace provider = score::crypto::daemon::provider;
namespace handler = score::crypto::daemon::provider::handler;

// ---------------------------------------------------------------------------
// Helper: build a Pkcs11Provider that is already Initialize()'d.
// ---------------------------------------------------------------------------
static std::shared_ptr<pkcs11_ns::Pkcs11Provider> MakeProvider(const std::string& label, const std::string& pin)
{
    pkcs11_ns::Pkcs11ProviderConfig cfg{};
    cfg.tokenLabel = label;
    cfg.userPin = pin;
    cfg.providerName = "SOFTHSM_TEST";

    auto provider = std::make_shared<pkcs11_ns::Pkcs11Provider>(std::move(cfg));
    return provider;
}

// ===========================================================================
// Test fixture: extends SofthsmTestFixture, adds a Pkcs11Provider + executor
// ===========================================================================
class Pkcs11KeyHandlerTest : public tests::softhsm::SofthsmTestFixture
{
  protected:
    std::shared_ptr<pkcs11_ns::Pkcs11Provider> m_provider;
    std::shared_ptr<pkcs11_ns::Pkcs11KeyManagementHandler> m_km_handler;
    std::shared_ptr<dm::DataManager> m_data_manager;
    km::KeyManagementService::Sptr m_service;
    km::SlotRegistry::Sptr m_slot_registry;
    dm::DataNodeId m_parent_id{0U};

    static constexpr dm::ClientId kClient = (42ULL << 32) | 1000ULL;

    void SetUp() override
    {
        SofthsmTestFixture::SetUp();
        if (HasFatalFailure())
        {
            return;
        }

        m_provider = MakeProvider("Test Token", "1234");
        ASSERT_TRUE(m_provider->Initialize(provider::ProviderInitContext{1, "SOFTHSM_TEST"}))
            << "Pkcs11Provider::Initialize() failed";

        m_data_manager = std::make_shared<dm::DataManager>();
        m_slot_registry = std::make_shared<km::SlotRegistry>();
        m_service = std::make_shared<km::KeyManagementService>(m_data_manager, nullptr, m_slot_registry);

        // Register a placeholder parent node.
        auto parent_node = std::make_shared<dm::DataNode>(/*exclusiveAccess=*/false);
        auto reg = m_data_manager->addNode(kClient, parent_node);
        ASSERT_TRUE(reg.has_value());
        m_parent_id = reg.value();

        // Inject the service into the provider so the factory can use it.
        m_provider->SetKeyManagementService(m_service);

        // Create key management handler via factory pattern.
        auto factory = m_provider->GetCryptoHandlerFactory();
        ASSERT_NE(factory, nullptr);

        auto handler_result = factory->CreateHandler(pkcs11_ns::kKeyManagementHandlerId, "");
        ASSERT_TRUE(handler_result.has_value()) << "CreateHandler failed for key management";
        auto handler = handler_result.value();
        m_km_handler = std::dynamic_pointer_cast<pkcs11_ns::Pkcs11KeyManagementHandler>(handler);
        ASSERT_NE(m_km_handler, nullptr);

        // Initialize handler context with client identity and assigned node IDs
        handler::InitializationParams init_params{.client_id = kClient,
                                                  .context_node_id = m_parent_id,
                                                  .provider_id = 1,
                                                  .key_node_id = 0U,
                                                  .bound_key_handler = nullptr};
        auto init_result = m_km_handler->InitializeContext(init_params);
        ASSERT_TRUE(init_result.has_value()) << "InitializeContext failed";
    }

    void TearDown() override
    {
        m_km_handler.reset();
        m_service.reset();
        m_data_manager.reset();
        if (m_provider)
        {
            m_provider->Shutdown();
            m_provider.reset();
        }
        SofthsmTestFixture::TearDown();
    }

    /// Build parameters for the operation. Context (client_id, context_node_id) comes from InitializeContext().
    void SetStandardParams(common::RequestParameters& params) const
    {
        params.clear();
        // Do NOT include context_id, client_id, or parent_id here
        // These are set via InitializeContext() on the handler
    }

    /// Register a slot and return its DataNodeId.
    dm::DataNodeId RegisterSlotNode(const km::KeySlotConfig& slot_cfg)
    {
        km::SlotHandle handle = m_slot_registry->RegisterSlot(slot_cfg);
        auto slot_node = std::make_shared<km::KeySlotDataNode>(handle, m_slot_registry);
        auto node_id = m_data_manager->addNode(kClient, std::move(slot_node));
        return node_id.has_value() ? node_id.value() : 0U;
    }
};

// ===========================================================================
// Test 1 — GenerateKey_AES256_ReturnsHandle
// ===========================================================================
/// Generates an ephemeral AES-256 key on the PKCS#11 token via KEY_GENERATE.
TEST_F(Pkcs11KeyHandlerTest, GenerateKey_AES256_ReturnsHandle)
{
    common::RequestParameters params;
    SetStandardParams(params);
    const std::string algo = "AES-256";
    params.push_back(std::string_view(algo));
    params.push_back(static_cast<std::uint64_t>(score::mw::crypto::KeyOperationPermission::kEncrypt));

    auto result = m_km_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_GENERATE}, params);
    ASSERT_TRUE(result.has_value()) << "KEY_GENERATE AES-256 failed";
    ASSERT_FALSE(result.value().empty());
    const auto key_node_id = std::get<std::uint64_t>(result.value()[0]);
    EXPECT_NE(key_node_id, 0U);

    // Cleanup: release via KEY_RELEASE
    common::RequestParameters rel_params;
    SetStandardParams(rel_params);
    rel_params.push_back(static_cast<std::uint64_t>(key_node_id));
    auto rel = m_km_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_RELEASE}, rel_params);
    EXPECT_TRUE(rel.has_value());
}

// ===========================================================================
// Test 2 — HmacSha256_GenerateAndRelease_FullLifecycle
// ===========================================================================
/// Generates a HMAC-SHA256 key and then releases it via Execute.
TEST_F(Pkcs11KeyHandlerTest, HmacSha256_GenerateAndRelease_FullLifecycle)
{
    common::RequestParameters gen_params;
    SetStandardParams(gen_params);
    const std::string algo = "HMAC-SHA256";
    gen_params.push_back(std::string_view(algo));
    gen_params.push_back(static_cast<std::uint64_t>(score::mw::crypto::KeyOperationPermission::kMac));

    auto gen = m_km_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_GENERATE}, gen_params);
    ASSERT_TRUE(gen.has_value()) << "KEY_GENERATE HMAC-SHA256 failed";
    const auto key_node_id = std::get<std::uint64_t>(gen.value()[0]);
    EXPECT_NE(key_node_id, 0U);

    // Release
    common::RequestParameters rel_params;
    SetStandardParams(rel_params);
    rel_params.push_back(static_cast<std::uint64_t>(key_node_id));

    auto release = m_km_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_RELEASE}, rel_params);
    EXPECT_TRUE(release.has_value()) << "KEY_RELEASE failed";
}

// ===========================================================================
// Test 3 — LoadKey_ByLabel_ReturnsHandle (native PKCS#11 path)
// ===========================================================================
/// Pre-creates a persistent (CKA_TOKEN=true) HMAC key with label "test_hmac"
/// on the token, then calls KEY_LOAD via Execute.
TEST_F(Pkcs11KeyHandlerTest, LoadKey_ByLabel_ReturnsHandle)
{
    const std::string label = "test_hmac";
    std::vector<uint8_t> key_bytes(32, 0xAA);

    const CK_OBJECT_HANDLE token_obj = CreateTokenKey(key_bytes, label, CKK_GENERIC_SECRET, /*extractable=*/false);
    ASSERT_NE(token_obj, static_cast<CK_OBJECT_HANDLE>(CK_INVALID_HANDLE)) << "Pre-creating the token key failed";

    km::KeySlotConfig slot{};
    slot.slot_name = "test/hmac_slot";
    slot.algorithm = "HMAC-SHA256";
    // Config-time: populate provider names; runtime would populate provider_ids via ResolveProviderIds
    slot.provider_names = {"SOFTHSM_TEST"};
    slot.provider_ids = {1};  // 1 = SoftHSM (assuming default registration order)
    slot.allowed_operations = score::mw::crypto::KeyOperationPermission::kMac;
    slot.access_policy.allowed_uids.push_back(static_cast<uint32_t>(kClient & 0xFFFFFFFFU));
    // Write a temporary deployment descriptor containing the PKCS#11 label.
    const std::string deploy_path =
        std::string{std::filesystem::temp_directory_path().string()} + "/test_pkcs11_hmac_slot.kv";
    {
        std::ofstream f(deploy_path);
        f << "[metadata]\navailability=active\n[key]\n"
          << std::string{km::deployment_keys::kPkcs11Label} << "=" << label << "\n";
    }
    slot.deployment_path = deploy_path;
    slot.deployment_format = "kv";

    const auto slot_node_id = RegisterSlotNode(slot);
    ASSERT_NE(slot_node_id, 0U);

    common::RequestParameters load_params;
    SetStandardParams(load_params);
    load_params.push_back(static_cast<std::uint64_t>(slot_node_id));

    auto result = m_km_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_LOAD}, load_params);
    ASSERT_TRUE(result.has_value()) << "KEY_LOAD failed";
    ASSERT_FALSE(result.value().empty());
    const auto key_node_id = std::get<std::uint64_t>(result.value()[0]);
    EXPECT_NE(key_node_id, 0U);
}

// ===========================================================================
// Test 4 — LoadKey_ExtractableKey_ReturnsNativeHandle
// ===========================================================================
/// Pre-creates an EXTRACTABLE persistent HMAC key, then verifies LoadKey still
/// returns a valid handle (extractability does not affect slot handler dispatch).
TEST_F(Pkcs11KeyHandlerTest, LoadKey_ExtractableKey_ReturnsNativeHandle)
{
    const std::string label = "test_hmac_extractable";
    std::vector<uint8_t> key_bytes(32, 0xCC);

    const CK_OBJECT_HANDLE token_obj = CreateTokenKey(key_bytes, label, CKK_GENERIC_SECRET, /*extractable=*/true);
    ASSERT_NE(token_obj, static_cast<CK_OBJECT_HANDLE>(CK_INVALID_HANDLE))
        << "Pre-creating the extractable token key failed";

    km::KeySlotConfig slot{};
    slot.slot_name = "test/hmac_extract_slot";
    slot.algorithm = "HMAC-SHA256";
    // Config-time: populate provider names; runtime would populate provider_ids via ResolveProviderIds
    slot.provider_names = {"SOFTHSM_TEST"};
    slot.provider_ids = {1};  // 1 = SoftHSM (assuming default registration order)
    slot.allowed_operations = score::mw::crypto::KeyOperationPermission::kMac;
    slot.access_policy.allowed_uids.push_back(static_cast<uint32_t>(kClient & 0xFFFFFFFFU));
    // Write a temporary deployment descriptor containing the PKCS#11 label.
    const std::string deploy_path =
        std::string{std::filesystem::temp_directory_path().string()} + "/test_pkcs11_hmac_extract_slot.kv";
    {
        std::ofstream f(deploy_path);
        f << "[metadata]\navailability=active\n[key]\n"
          << std::string{km::deployment_keys::kPkcs11Label} << "=" << label << "\n";
    }
    slot.deployment_path = deploy_path;
    slot.deployment_format = "kv";

    const auto slot_node_id = RegisterSlotNode(slot);
    ASSERT_NE(slot_node_id, 0U);

    common::RequestParameters load_params;
    SetStandardParams(load_params);
    load_params.push_back(static_cast<std::uint64_t>(slot_node_id));

    auto result = m_km_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_LOAD}, load_params);
    ASSERT_TRUE(result.has_value()) << "KEY_LOAD (extractable key) failed: " << static_cast<int>(result.error());
    ASSERT_FALSE(result.value().empty());
    EXPECT_NE(std::get<std::uint64_t>(result.value()[0]), 0U);
}

// ---------------------------------------------------------------------------
// Main entry point: @googletest//:gtest_main supplies main()
// ---------------------------------------------------------------------------

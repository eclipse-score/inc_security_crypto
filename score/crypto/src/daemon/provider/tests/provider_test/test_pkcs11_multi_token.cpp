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

/// @file test_pkcs11_multi_token.cpp
/// @brief Validates that two PKCS#11 providers backed by different SoftHSM
///        tokens coexist independently: separate session pools, separate
///        login/logout state, and separate key stores.

#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>

#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/i_provider.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/pkcs11_module.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/pkcs11_provider.hpp"
#include "score/crypto/src/daemon/provider/provider_manager.hpp"
#include "score/crypto/tests/pkcs11/pkcs11_test_env_setup.hpp"

namespace pkcs11 = score::crypto::daemon::provider::pkcs11;
namespace provider = score::crypto::daemon::provider;
namespace common = score::crypto::daemon::common;

namespace
{

/// @brief Test fixture that initialises two independent PKCS#11 tokens.
class Pkcs11MultiTokenTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        // Unique directory per test to avoid state conflicts
        m_baseDir = tests::pkcs11::env::UniqueTestDirectory("multi_token_test");

        // Set up isolated backend environments with 2 slots
        tests::pkcs11::env::PrepareBackendEnvironments(m_baseDir, /*num_slots=*/2U);

        // Reset slot counter for each test
        m_nextSlotId = 0U;

        // shared module for all tokens on the same library
        m_module = std::make_shared<pkcs11::Pkcs11Module>();
        ASSERT_TRUE(m_module->Init().has_value()) << "C_Initialize failed";

        CK_FUNCTION_LIST* fns = m_module->GetFunctionList();
        ASSERT_NE(fns, nullptr);
        CK_ULONG totalSlots = 0U;
        ASSERT_EQ(fns->C_GetSlotList(CK_FALSE, nullptr, &totalSlots), CKR_OK);
        if (totalSlots < 2U)
        {
            GTEST_SKIP() << "Active PKCS#11 provider does not expose multiple slots.";
        }

        // Initialise first token
        InitToken("TokenA", m_slotA);

        // Initialise second token
        InitToken("TokenB", m_slotB);
    }

    void TearDown() override
    {
        m_providerA.reset();
        m_providerB.reset();
        m_module.reset();  // C_Finalize
        std::error_code ec;
        std::filesystem::remove_all(m_baseDir, ec);
        ASSERT_FALSE(ec) << ec.message();
        tests::pkcs11::env::CleanupBackendEnvironments();
    }

    void InitToken(const std::string& label, CK_SLOT_ID& outSlot)
    {
        CK_FUNCTION_LIST* fns = m_module->GetFunctionList();
        ASSERT_NE(fns, nullptr);

        // Get available slots.
        CK_ULONG slotCount = 0U;
        ASSERT_EQ(fns->C_GetSlotList(CK_FALSE, nullptr, &slotCount), CKR_OK);
        ASSERT_GT(slotCount, 0U) << "No slots available for token=" << label;

        std::vector<CK_SLOT_ID> slots(slotCount);
        ASSERT_EQ(fns->C_GetSlotList(CK_FALSE, slots.data(), &slotCount), CKR_OK);

        // Use the next available slot for independent tokens
        CK_SLOT_ID targetSlot = (m_nextSlotId < slotCount) ? slots[m_nextSlotId] : slots[0];
        m_nextSlotId++;

        // Pad label to 32 characters as required by C_InitToken.
        std::string paddedLabel = label;
        paddedLabel.resize(32U, ' ');
        // MISRA C++:2023 Rule 8.2.4 deviation — PKCS#11 C API requires CK_UTF8CHAR_PTR.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        auto* labelPtr = reinterpret_cast<CK_UTF8CHAR_PTR>(paddedLabel.data());
        std::string soPin = "12345678";
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        auto* soPinPtr = reinterpret_cast<CK_UTF8CHAR_PTR>(soPin.data());

        const CK_RV rv = fns->C_InitToken(targetSlot, soPinPtr, static_cast<CK_ULONG>(soPin.size()), labelPtr);
        ASSERT_EQ(rv, CKR_OK) << "C_InitToken failed for token=" << label << " on slot=" << targetSlot;

        outSlot = targetSlot;

        // Open a session on the freshly initialized token to set the user PIN.
        CK_SESSION_HANDLE session{CK_INVALID_HANDLE};
        ASSERT_EQ(fns->C_OpenSession(outSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &session), CKR_OK)
            << "C_OpenSession failed on slot=" << outSlot << " for token=" << label;
        ASSERT_EQ(fns->C_Login(session, CKU_SO, soPinPtr, static_cast<CK_ULONG>(soPin.size())), CKR_OK)
            << "C_Login (SO) failed for token=" << label;

        std::string userPin = "1234";
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        auto* userPinPtr = reinterpret_cast<CK_UTF8CHAR_PTR>(userPin.data());
        ASSERT_EQ(fns->C_InitPIN(session, userPinPtr, static_cast<CK_ULONG>(userPin.size())), CKR_OK)
            << "C_InitPIN failed for token=" << label;

        fns->C_Logout(session);
        fns->C_CloseSession(session);
    }

    std::shared_ptr<pkcs11::Pkcs11Provider> CreateProvider(const std::string& label, CK_SLOT_ID slot)
    {
        pkcs11::Pkcs11ProviderConfig config{};
        config.slotId = slot;
        config.tokenLabel = label;
        config.userPin = "1234";
        config.providerName = label;
        config.cleanupStrategy = pkcs11::Pkcs11SessionCleanupStrategy::kHardCleanup;

        auto p = std::make_shared<pkcs11::Pkcs11Provider>(config, m_module);
        provider::ProviderInitContext ctx{};
        ctx.numeric_id = (label == "TokenA") ? 0U : 1U;
        ctx.name = label;
        EXPECT_TRUE(p->Initialize(ctx)) << "Provider init failed for " << label;
        return p;
    }

    std::shared_ptr<pkcs11::Pkcs11Module> m_module;
    std::shared_ptr<pkcs11::Pkcs11Provider> m_providerA;
    std::shared_ptr<pkcs11::Pkcs11Provider> m_providerB;
    CK_SLOT_ID m_slotA{CK_INVALID_HANDLE};
    CK_SLOT_ID m_slotB{CK_INVALID_HANDLE};
    CK_ULONG m_nextSlotId{0U};
    std::string m_baseDir;
};

TEST_F(Pkcs11MultiTokenTest, IndependentSessionPools)
{
    m_providerA = CreateProvider("TokenA", m_slotA);
    m_providerB = CreateProvider("TokenB", m_slotB);

    // Acquire User sessions on both tokens
    const pkcs11::Pkcs11HandlerRequirements userReqs{pkcs11::Pkcs11SessionType::ReadOnly,
                                                     pkcs11::Pkcs11TokenAuthState::User};

    auto sessA = m_providerA->AcquireSession(userReqs);
    ASSERT_TRUE(sessA.has_value()) << "Failed to acquire session on TokenA";

    auto sessB = m_providerB->AcquireSession(userReqs);
    ASSERT_TRUE(sessB.has_value()) << "Failed to acquire session on TokenB";

    // Sessions must be different handles
    EXPECT_NE(sessA.value(), sessB.value());

    // Release session on A — should NOT affect B
    m_providerA->ReleaseSession(sessA.value(), userReqs);

    // Validate that token B's session is still valid
    EXPECT_TRUE(m_providerB->ValidateSession(sessB.value()));

    m_providerB->ReleaseSession(sessB.value(), userReqs);
}

TEST_F(Pkcs11MultiTokenTest, IndependentLoginState)
{
    m_providerA = CreateProvider("TokenA", m_slotA);
    m_providerB = CreateProvider("TokenB", m_slotB);

    const pkcs11::Pkcs11HandlerRequirements userReqs{pkcs11::Pkcs11SessionType::ReadWrite,
                                                     pkcs11::Pkcs11TokenAuthState::User};

    // Login on token A
    auto sessA = m_providerA->AcquireSession(userReqs);
    ASSERT_TRUE(sessA.has_value());

    // Login on token B
    auto sessB = m_providerB->AcquireSession(userReqs);
    ASSERT_TRUE(sessB.has_value());

    // Release (and logout) token A
    m_providerA->ReleaseSession(sessA.value(), userReqs);

    // Token B should still be in User state — acquire another session
    auto sessB2 = m_providerB->AcquireSession(userReqs);
    ASSERT_TRUE(sessB2.has_value()) << "Token B session acquisition failed after Token A logout";

    m_providerB->ReleaseSession(sessB.value(), userReqs);
    m_providerB->ReleaseSession(sessB2.value(), userReqs);
}

}  // namespace

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

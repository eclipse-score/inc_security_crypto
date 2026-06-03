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

#include "score/crypto/daemon/key_management/interfaces/key_slot_config.hpp"
#include "score/crypto/daemon/key_management/slot/access_policy_enforcer.hpp"
#include "score/mw/crypto/api/common/types.hpp"

#include <gtest/gtest.h>

namespace km = score::crypto::daemon::key_management;

class AccessPolicyEnforcerTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        m_slot_config.slot_name = "test/hmac-sha256";
        m_slot_config.algorithm = "HMAC-SHA256";
        // Config-time: populate provider names (strings from configuration)
        m_slot_config.provider_names = {score::crypto::daemon::common::kProviderNameOpenSSL};
        // Test setup: simulate resolved provider IDs (would normally be done by ResolveProviderIds)
        m_slot_config.provider_ids = {0};  // 0 = OpenSSL, assigned by ProviderManager
        m_slot_config.allowed_operations = score::mw::crypto::KeyOperationPermission::kMac;
        m_slot_config.access_policy.allowed_uids = {0, 1000, 2000};
    }

    km::KeySlotConfig m_slot_config;
};

// ============================================================================
// CheckSlotAccess tests
// ============================================================================

TEST_F(AccessPolicyEnforcerTest, CheckSlotAccess_AllowedUid_Succeeds)
{
    // UID is extracted from the upper 32 bits of client_id by GetUidFromClientId
    uint64_t client_id = static_cast<uint64_t>(1000U) << 32U;
    auto result = km::AccessPolicyEnforcer::CheckSlotAccess(m_slot_config, client_id);
    ASSERT_TRUE(result.has_value());
}

TEST_F(AccessPolicyEnforcerTest, CheckSlotAccess_RootUid_Succeeds)
{
    auto result = km::AccessPolicyEnforcer::CheckSlotAccess(m_slot_config, 0U);
    ASSERT_TRUE(result.has_value());
}

TEST_F(AccessPolicyEnforcerTest, CheckSlotAccess_DisallowedUid_Fails)
{
    // UID is extracted from the upper 32 bits of client_id by GetUidFromClientId
    uint64_t client_id = static_cast<uint64_t>(9999U) << 32U;
    auto result = km::AccessPolicyEnforcer::CheckSlotAccess(m_slot_config, client_id);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kAccessDenied);
}

TEST_F(AccessPolicyEnforcerTest, CheckSlotAccess_UidInUpperBits_ExtractsUpper32)
{
    // UID=1000 in upper 32 bits, PID=5555 in lower 32 bits
    uint64_t composite_client_id = (static_cast<uint64_t>(1000) << 32U) | 5555U;
    auto result = km::AccessPolicyEnforcer::CheckSlotAccess(m_slot_config, composite_client_id);
    ASSERT_TRUE(result.has_value());
}

// ============================================================================
// CheckOperationPermission tests
// ============================================================================

TEST_F(AccessPolicyEnforcerTest, CheckOperationPermission_Mac_Succeeds)
{
    auto result = km::AccessPolicyEnforcer::CheckOperationPermission(m_slot_config,
                                                                     score::mw::crypto::KeyOperationPermission::kMac);
    ASSERT_TRUE(result.has_value());
}

TEST_F(AccessPolicyEnforcerTest, CheckOperationPermission_None_Succeeds)
{
    // kNone means no specific permission is requested → always passes
    auto result = km::AccessPolicyEnforcer::CheckOperationPermission(m_slot_config,
                                                                     score::mw::crypto::KeyOperationPermission::kNone);
    ASSERT_TRUE(result.has_value());
}

TEST_F(AccessPolicyEnforcerTest, CheckOperationPermission_Encrypt_FailsOnMacOnlySlot)
{
    auto result = km::AccessPolicyEnforcer::CheckOperationPermission(
        m_slot_config, score::mw::crypto::KeyOperationPermission::kEncrypt);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kKeyOperationNotPermitted);
}

// ============================================================================
// Authorize (combined) tests
// ============================================================================

TEST_F(AccessPolicyEnforcerTest, Authorize_ValidUidAndPermission_Succeeds)
{
    uint64_t client_id = static_cast<uint64_t>(1000U) << 32U;
    auto result =
        km::AccessPolicyEnforcer::Authorize(m_slot_config, client_id, score::mw::crypto::KeyOperationPermission::kMac);
    ASSERT_TRUE(result.has_value());
}

TEST_F(AccessPolicyEnforcerTest, Authorize_InvalidUid_Fails)
{
    // UID is extracted from the upper 32 bits of client_id by GetUidFromClientId
    uint64_t client_id = static_cast<uint64_t>(9999U) << 32U;
    auto result =
        km::AccessPolicyEnforcer::Authorize(m_slot_config, client_id, score::mw::crypto::KeyOperationPermission::kMac);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kAccessDenied);
}

TEST_F(AccessPolicyEnforcerTest, Authorize_InvalidPermission_Fails)
{
    uint64_t client_id = static_cast<uint64_t>(1000U) << 32U;
    auto result = km::AccessPolicyEnforcer::Authorize(
        m_slot_config, client_id, score::mw::crypto::KeyOperationPermission::kEncrypt);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kKeyOperationNotPermitted);
}

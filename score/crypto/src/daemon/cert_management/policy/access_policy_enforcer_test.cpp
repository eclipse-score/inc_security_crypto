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

#include "score/crypto/src/daemon/cert_management/policy/access_policy_enforcer.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_slot_config.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/trust_store_config.hpp"
#include <gtest/gtest.h>

#include <cstdint>
#include <optional>

namespace
{
using namespace score::crypto::daemon::cert_management;

score::crypto::daemon::data_manager::ClientId ClientId(std::uint32_t pid, std::uint32_t uid)
{
    union
    {
        score::crypto::daemon::data_manager::ClientId id;
        struct
        {
            std::uint32_t process_id;
            std::uint32_t user_id;
        } parts;
    } value{0U};
    value.parts.process_id = pid;
    value.parts.user_id = uid;
    return value.id;
}

TEST(AccessPolicyEnforcerTest, AllowsUnrestrictedSlotRead)
{
    CertSlotConfig slot;
    EXPECT_TRUE(AccessPolicyEnforcer::CheckSlotAccess(slot, ClientId(100U, 200U)).has_value());
}

// std::nullopt configures an empty write allowlist.
struct WriteAuthorizationCase
{
    std::optional<std::uint32_t> permitted_uid;
    std::uint32_t requesting_uid;
    bool expect_success;
};

class SlotWriteAuthorizationTest : public ::testing::TestWithParam<WriteAuthorizationCase>
{
};

TEST_P(SlotWriteAuthorizationTest, ChecksWriteAgainstAllowlist)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_mgmt__access_control");
    RecordProperty("Description", "A certificate slot grants writes only to UIDs listed in its write allowlist.");
    RecordProperty("TestType", "interface-test");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto& param = GetParam();
    CertSlotConfig slot;
    if (param.permitted_uid.has_value())
    {
        slot.access_policy.allowed_write_uids = {*param.permitted_uid};
    }

    const auto result = AccessPolicyEnforcer::CheckWritePermission(slot, ClientId(1U, param.requesting_uid));
    EXPECT_EQ(result.has_value(), param.expect_success);
}

INSTANTIATE_TEST_SUITE_P(SlotWriteAuthorization,
                         SlotWriteAuthorizationTest,
                         ::testing::Values(WriteAuthorizationCase{100U, 200U, false},
                                           WriteAuthorizationCase{200U, 200U, true},
                                           WriteAuthorizationCase{std::nullopt, 200U, false}));

TEST(AccessPolicyEnforcerTest, AllowsUnrestrictedTrustStoreRead)
{
    TrustStoreConfig store;
    EXPECT_TRUE(AccessPolicyEnforcer::CheckTrustStoreAccess(store, ClientId(1U, 200U)).has_value());
}

class TrustStoreWriteAuthorizationTest : public ::testing::TestWithParam<WriteAuthorizationCase>
{
};

TEST_P(TrustStoreWriteAuthorizationTest, ChecksWriteAgainstAllowlist)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_mgmt__access_control");
    RecordProperty("Description", "A trust store grants writes only to UIDs listed in its write allowlist.");
    RecordProperty("TestType", "interface-test");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto& param = GetParam();
    TrustStoreConfig store;
    if (param.permitted_uid.has_value())
    {
        store.access_policy.allowed_write_uids = {*param.permitted_uid};
    }

    const auto result = AccessPolicyEnforcer::CheckTrustStoreWritePermission(store, ClientId(1U, param.requesting_uid));
    EXPECT_EQ(result.has_value(), param.expect_success);
}

INSTANTIATE_TEST_SUITE_P(TrustStoreWriteAuthorization,
                         TrustStoreWriteAuthorizationTest,
                         ::testing::Values(WriteAuthorizationCase{100U, 200U, false},
                                           WriteAuthorizationCase{200U, 200U, true},
                                           WriteAuthorizationCase{std::nullopt, 200U, false}));
}  // namespace

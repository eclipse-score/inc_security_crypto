#include "score/crypto/src/daemon/cert_management/interfaces/cert_slot_config.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/trust_store_config.hpp"
#include "score/crypto/src/daemon/cert_management/policy/access_policy_enforcer.hpp"
#include <gtest/gtest.h>

#include <cstdint>

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

TEST(AccessPolicyEnforcerTest, DeniesSlotWriteWhenUidIsNotAllowed)
{
    CertSlotConfig slot;
    slot.access_policy.allowed_write_uids = {100U};

    EXPECT_FALSE(AccessPolicyEnforcer::CheckWritePermission(slot, ClientId(1U, 200U)).has_value());
}

TEST(AccessPolicyEnforcerTest, AllowsSlotWriteForConfiguredUid)
{
    CertSlotConfig slot;
    slot.access_policy.allowed_write_uids = {200U};

    EXPECT_TRUE(AccessPolicyEnforcer::CheckWritePermission(slot, ClientId(1U, 200U)).has_value());
}

TEST(AccessPolicyEnforcerTest, AllowsUnrestrictedTrustStoreRead)
{
    TrustStoreConfig store;
    EXPECT_TRUE(AccessPolicyEnforcer::CheckTrustStoreAccess(store, ClientId(1U, 200U)).has_value());
}

TEST(AccessPolicyEnforcerTest, DeniesTrustStoreWriteWhenAllowlistIsEmpty)
{
    TrustStoreConfig store;
    EXPECT_FALSE(AccessPolicyEnforcer::CheckTrustStoreWritePermission(store, ClientId(1U, 200U)).has_value());
}

TEST(AccessPolicyEnforcerTest, AllowsTrustStoreWriteForConfiguredUid)
{
    TrustStoreConfig store;
    store.access_policy.allowed_write_uids = {200U};

    EXPECT_TRUE(AccessPolicyEnforcer::CheckTrustStoreWritePermission(store, ClientId(1U, 200U)).has_value());
}
}  // namespace

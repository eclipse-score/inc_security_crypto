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

#include "score/crypto/src/daemon/config/inc/config.hpp"

#include <gtest/gtest.h>

namespace common = score::crypto::daemon::common;
namespace config = score::crypto::daemon::config;

TEST(ProviderPolicyTest, EmptyConstructionPolicyAllowsDiscoveredProviders)
{
    const config::ProviderConstructionPolicy policy;

    EXPECT_TRUE(policy.Validate());
    EXPECT_TRUE(policy.IsProviderEnabled("OPENSSL"));
    EXPECT_TRUE(policy.IsProviderEnabled("HSM"));
}

TEST(ProviderPolicyTest, ExplicitConstructionPolicyAllowsOnlyEnabledEntries)
{
    config::ProviderConstructionPolicy policy;
    policy.AddProvider(config::ProviderConstructionEntry{"OPENSSL", true, false});
    policy.AddProvider(config::ProviderConstructionEntry{"HSM", false, false});

    EXPECT_TRUE(policy.Validate());
    EXPECT_TRUE(policy.IsProviderEnabled("OPENSSL"));
    EXPECT_FALSE(policy.IsProviderEnabled("HSM"));
    EXPECT_FALSE(policy.IsProviderEnabled("UNLISTED"));
}

TEST(ProviderPolicyTest, ConstructionPolicyRejectsEmptyDuplicateAndDisabledRequiredEntries)
{
    config::ProviderConstructionPolicy empty_name;
    empty_name.AddProvider(config::ProviderConstructionEntry{"", true, false});
    EXPECT_FALSE(empty_name.Validate());

    config::ProviderConstructionPolicy duplicate;
    duplicate.AddProvider(config::ProviderConstructionEntry{"OPENSSL", true, false});
    duplicate.AddProvider(config::ProviderConstructionEntry{"OPENSSL", true, true});
    EXPECT_FALSE(duplicate.Validate());

    config::ProviderConstructionPolicy disabled_required;
    disabled_required.AddProvider(config::ProviderConstructionEntry{"HSM", false, true});
    EXPECT_FALSE(disabled_required.Validate());
}

TEST(ProviderPolicyTest, RoutingPolicyRejectsDisabledDefaultAndInvalidPreferences)
{
    config::ProviderConstructionPolicy construction;
    construction.AddProvider(config::ProviderConstructionEntry{"OPENSSL", true, false});
    construction.AddProvider(config::ProviderConstructionEntry{"HSM", false, false});

    config::ProviderRoutingPolicy disabled_default;
    disabled_default.SetDefaultProviderForType(common::CryptoProviderType::DEFAULT, "HSM");
    EXPECT_FALSE(disabled_default.Validate(construction));

    config::ProviderRoutingPolicy duplicate_preference;
    duplicate_preference.defaultProviderPreference = {common::CryptoProviderType::SOFTWARE,
                                                      common::CryptoProviderType::SOFTWARE};
    EXPECT_FALSE(duplicate_preference.Validate(construction));

    config::ProviderRoutingPolicy recursive_default;
    recursive_default.defaultProviderPreference = {common::CryptoProviderType::DEFAULT};
    EXPECT_FALSE(recursive_default.Validate(construction));

    config::ProviderRoutingPolicy unknown_type;
    unknown_type.SetDefaultProviderForType(static_cast<common::CryptoProviderType>(0xFFU), "OPENSSL");
    EXPECT_FALSE(unknown_type.Validate(construction));

    config::ProviderRoutingPolicy unknown_preference;
    unknown_preference.defaultProviderPreference = {static_cast<common::CryptoProviderType>(0xFFU)};
    EXPECT_FALSE(unknown_preference.Validate(construction));
}

TEST(ProviderPolicyTest, RoutingPolicyAcceptsCapabilityCombinationsAndRejectsUnknownBits)
{
    const config::ProviderConstructionPolicy construction;

    config::ProviderRoutingPolicy combined_capability;
    combined_capability
        .capabilityRouting[common::ProviderCapability::kCrypto | common::ProviderCapability::kKeyManagement] =
        config::CapabilityRoutingRule{{common::CryptoProviderType::SOFTWARE}, true};
    EXPECT_TRUE(combined_capability.Validate(construction));

    config::ProviderRoutingPolicy unknown_capability;
    unknown_capability.capabilityRouting[static_cast<common::ProviderCapability>(0x80U)] =
        config::CapabilityRoutingRule{{common::CryptoProviderType::SOFTWARE}, true};
    EXPECT_FALSE(unknown_capability.Validate(construction));

    config::ProviderRoutingPolicy non_routable;
    non_routable.SetCapabilityRouting(common::ProviderCapability::kCrypto, config::CapabilityRoutingRule{{}, false});
    EXPECT_FALSE(non_routable.Validate(construction));

    config::ProviderRoutingPolicy duplicate_capability_preference;
    duplicate_capability_preference.SetCapabilityRouting(
        common::ProviderCapability::kCrypto,
        config::CapabilityRoutingRule{{common::CryptoProviderType::HARDWARE, common::CryptoProviderType::HARDWARE},
                                      true});
    EXPECT_FALSE(duplicate_capability_preference.Validate(construction));
}

TEST(ProviderPolicyTest, ConfigValidationCombinesConstructionAndRoutingPolicies)
{
    config::Config daemon_config;
    daemon_config.GetProviderConstructionPolicy().AddProvider(
        config::ProviderConstructionEntry{"OPENSSL", true, false});
    daemon_config.GetProviderRoutingPolicy().SetDefaultProviderForType(common::CryptoProviderType::DEFAULT, "OPENSSL");
    EXPECT_TRUE(daemon_config.Validate());

    daemon_config.GetProviderRoutingPolicy().SetDefaultProviderForType(common::CryptoProviderType::HARDWARE,
                                                                       "UNLISTED_HSM");
    EXPECT_FALSE(daemon_config.Validate());
}

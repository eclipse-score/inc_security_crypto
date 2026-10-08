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

#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"

#include <gtest/gtest.h>

namespace score::crypto::daemon::mediator::operations
{
namespace
{

using ProviderType = common::CryptoProviderType;

TEST(ProviderTypePreferenceTest, DecodesExactProviderTypesWithoutFallback)
{
    const auto hardware = DecodeProviderTypePreference(1U);
    ASSERT_TRUE(hardware.has_value());
    EXPECT_EQ(hardware->primary, ProviderType::HARDWARE);
    EXPECT_FALSE(hardware->fallback.has_value());

    const auto software = DecodeProviderTypePreference(2U);
    ASSERT_TRUE(software.has_value());
    EXPECT_EQ(software->primary, ProviderType::SOFTWARE);
    EXPECT_FALSE(software->fallback.has_value());
}

TEST(ProviderTypePreferenceTest, PreservesPreferredProviderFallbackOrder)
{
    const auto hardware_preferred = DecodeProviderTypePreference(3U);
    ASSERT_TRUE(hardware_preferred.has_value());
    EXPECT_EQ(hardware_preferred->primary, ProviderType::HARDWARE);
    ASSERT_TRUE(hardware_preferred->fallback.has_value());
    EXPECT_EQ(hardware_preferred->fallback.value(), ProviderType::SOFTWARE);

    const auto software_preferred = DecodeProviderTypePreference(4U);
    ASSERT_TRUE(software_preferred.has_value());
    EXPECT_EQ(software_preferred->primary, ProviderType::SOFTWARE);
    ASSERT_TRUE(software_preferred->fallback.has_value());
    EXPECT_EQ(software_preferred->fallback.value(), ProviderType::HARDWARE);
}

TEST(ProviderTypePreferenceTest, DecodesDefaultAndRejectsUnknownValues)
{
    const auto default_provider = DecodeProviderTypePreference(0U);
    ASSERT_TRUE(default_provider.has_value());
    EXPECT_EQ(default_provider->primary, ProviderType::DEFAULT);
    EXPECT_FALSE(default_provider->fallback.has_value());

    EXPECT_FALSE(DecodeProviderTypePreference(5U).has_value());
    EXPECT_FALSE(DecodeProviderTypePreference(255U).has_value());
}

}  // namespace
}  // namespace score::crypto::daemon::mediator::operations

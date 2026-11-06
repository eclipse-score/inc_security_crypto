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

#include "score/crypto/src/daemon/key_management/detail/slot_info_builder.hpp"

#include <gtest/gtest.h>

#include <string_view>

namespace score::crypto::daemon::key_management
{
namespace
{

KeySlotConfig MakeSlot()
{
    KeySlotConfig slot;
    slot.slot_name = "test/slot";
    slot.algorithm = "ECDSA-P256";
    slot.allowed_operations =
        score::crypto::KeyOperationPermission::kSign | score::crypto::KeyOperationPermission::kVerify;
    return slot;
}

TEST(SlotInfoBuilderTest, OccupiedSlot_ReportsConfigMetadata)
{
    auto slot = MakeSlot();
    slot.provider_ids = {3U};

    const auto info = detail::BuildKeySlotInfo(slot, score::crypto::KeySlotState::kOccupied);

    EXPECT_EQ(info.state, score::crypto::KeySlotState::kOccupied);
    EXPECT_EQ(std::string_view{info.algorithm}, "ECDSA-P256");
    EXPECT_EQ(info.permitted_operations, slot.allowed_operations);
    EXPECT_EQ(info.primary_provider, 3U);
    EXPECT_EQ(info.compatible_provider_count, 0U);
}

TEST(SlotInfoBuilderTest, EmptySlot_StillReportsAlgorithmConstraint)
{
    const auto info = detail::BuildKeySlotInfo(MakeSlot(), score::crypto::KeySlotState::kEmpty);

    EXPECT_EQ(info.state, score::crypto::KeySlotState::kEmpty);
    EXPECT_EQ(std::string_view{info.algorithm}, "ECDSA-P256");
}

TEST(SlotInfoBuilderTest, SecondaryProviders_AreReportedAsCompatible)
{
    auto slot = MakeSlot();
    slot.provider_ids = {1U, 2U, 5U};

    const auto info = detail::BuildKeySlotInfo(slot, score::crypto::KeySlotState::kOccupied);

    EXPECT_EQ(info.primary_provider, 1U);
    ASSERT_EQ(info.compatible_provider_count, 2U);
    EXPECT_EQ(info.compatible_providers[0], 2U);
    EXPECT_EQ(info.compatible_providers[1], 5U);
}

TEST(SlotInfoBuilderTest, CompatibleProviders_AreCappedAtCapacity)
{
    auto slot = MakeSlot();
    for (common::ProviderId id = 0U; id < 12U; ++id)
    {
        slot.provider_ids.push_back(id);
    }

    const auto info = detail::BuildKeySlotInfo(slot, score::crypto::KeySlotState::kOccupied);

    EXPECT_EQ(info.compatible_provider_count, score::crypto::KeySlotInfo::kMaxCompatibleProviders);
    EXPECT_EQ(info.compatible_providers.back(), 8U);
}

TEST(SlotInfoBuilderTest, NoResolvedProviders_LeavesProviderFieldsZero)
{
    const auto info = detail::BuildKeySlotInfo(MakeSlot(), score::crypto::KeySlotState::kOccupied);

    EXPECT_EQ(info.primary_provider, 0U);
    EXPECT_EQ(info.compatible_provider_count, 0U);
}

}  // namespace
}  // namespace score::crypto::daemon::key_management

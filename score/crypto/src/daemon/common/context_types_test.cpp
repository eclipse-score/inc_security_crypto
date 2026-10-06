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

/// @file context_types_test.cpp
/// @brief Verifies the classification every keyed context creation depends on.
///
/// RequiredKeyPermission() and IsKeylessContextType() split the context types
/// between them, and the mediator reads both to decide whether a key may bind.
/// A type missing from both is refused; a keyed type wrongly listed as keyless
/// binds without a permission check. Neither mistake shows up in an integration
/// test, because the client only ever sends well-known type strings.

#include "score/crypto/src/daemon/common/context_types.hpp"
#include "score/crypto/src/daemon/common/context_mode.hpp"

#include "score/crypto/src/api/types/common.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <optional>
#include <string_view>

namespace
{

namespace common = score::crypto::daemon::common;
namespace ctx = score::crypto::daemon::common::context_types;

using score::crypto::KeyOperationPermission;

/// Every context type the wire protocol defines.
constexpr std::string_view kAllContextTypes[] = {
    ctx::kHash,
    ctx::kMac,
    ctx::kCipher,
    ctx::kSign,
    ctx::kVerify,
    ctx::kRandom,
    ctx::kKeyManagement,
};

TEST(ContextTypesTest, EveryKnownTypeIsEitherKeylessOrCarriesAPermission)
{
    // The two functions must partition the set. A type in neither is refused at
    // key binding; a type in both would let the keyless branch win and skip the
    // permission check.
    for (const auto type : kAllContextTypes)
    {
        const bool keyless = common::IsKeylessContextType(type);
        const bool has_permission = common::RequiredKeyPermission(type, std::nullopt).has_value();

        EXPECT_NE(keyless, has_permission)
            << "context type '" << type << "' must be exactly one of keyless or permission-carrying";
    }
}

TEST(ContextTypesTest, UnknownTypeIsNeitherKeylessNorPermitted)
{
    // The case the mediator's fail-closed branch exists for: an unrecognised
    // type must not be mistaken for a keyless one, or it would bind any key
    // without a check.
    constexpr std::string_view kUnknown = "NOT_A_CONTEXT_TYPE";

    EXPECT_FALSE(common::IsKeylessContextType(kUnknown));
    EXPECT_FALSE(common::RequiredKeyPermission(kUnknown, std::nullopt).has_value());
    EXPECT_FALSE(common::IsKeylessContextType(""));
}

TEST(ContextTypesTest, KeyedTypesDemandTheOperationTheyPerform)
{
    EXPECT_EQ(common::RequiredKeyPermission(ctx::kMac, std::nullopt), KeyOperationPermission::kMac);
    EXPECT_EQ(common::RequiredKeyPermission(ctx::kSign, std::nullopt), KeyOperationPermission::kSign);
    EXPECT_EQ(common::RequiredKeyPermission(ctx::kVerify, std::nullopt), KeyOperationPermission::kVerify);
}

TEST(ContextTypesTest, CipherPermissionFollowsTheRequestedDirection)
{
    const auto encrypt = common::ContextMode::kEncrypt;
    const auto decrypt = common::ContextMode::kDecrypt;

    EXPECT_EQ(common::RequiredKeyPermission(ctx::kCipher, encrypt), KeyOperationPermission::kEncrypt);
    EXPECT_EQ(common::RequiredKeyPermission(ctx::kCipher, decrypt), KeyOperationPermission::kDecrypt);
}

TEST(ContextTypesTest, CipherWithoutADirectionDemandsBothHalves)
{
    // A cipher request that declined to say which direction it wanted is
    // malformed. Demanding both bits fails closed: a key granted only one
    // direction cannot slip through on it.
    const auto required = common::RequiredKeyPermission(ctx::kCipher, std::nullopt);

    ASSERT_TRUE(required.has_value());
    EXPECT_TRUE(score::crypto::HasPermission(required.value(), KeyOperationPermission::kEncrypt));
    EXPECT_TRUE(score::crypto::HasPermission(required.value(), KeyOperationPermission::kDecrypt));
}

/// A MAC/signature mode on a cipher context is malformed and fails closed to both bits.
TEST(ContextTypesTest, CipherWithSignatureModeFailsClosed)
{
    const auto both = KeyOperationPermission::kEncrypt | KeyOperationPermission::kDecrypt;
    EXPECT_EQ(common::RequiredKeyPermission(ctx::kCipher, common::ContextMode::kGenerate), both);
    EXPECT_EQ(common::RequiredKeyPermission(ctx::kCipher, common::ContextMode::kVerify), both);
}

/// The wire vocabulary round-trips both API enums and rejects anything outside it.
TEST(ContextModeTest, RoundTripsApiEnumsAndRejectsUnknownBytes)
{
    using score::crypto::CipherDirection;
    using score::crypto::OperationMode;

    EXPECT_EQ(common::ToCipherDirection(common::ToContextMode(CipherDirection::kEncrypt)), CipherDirection::kEncrypt);
    EXPECT_EQ(common::ToCipherDirection(common::ToContextMode(CipherDirection::kDecrypt)), CipherDirection::kDecrypt);
    EXPECT_EQ(common::ToOperationMode(common::ToContextMode(OperationMode::kGenerate)), OperationMode::kGenerate);
    EXPECT_EQ(common::ToOperationMode(common::ToContextMode(OperationMode::kVerify)), OperationMode::kVerify);

    // A cipher direction is not a MAC mode and the reverse.
    EXPECT_FALSE(common::ToOperationMode(common::ContextMode::kEncrypt).has_value());
    EXPECT_FALSE(common::ToCipherDirection(common::ContextMode::kGenerate).has_value());

    EXPECT_TRUE(common::ParseContextMode(static_cast<std::uint8_t>(common::ContextMode::kDecrypt)).has_value());
    EXPECT_FALSE(common::ParseContextMode(static_cast<std::uint8_t>(common::ContextMode::kDecrypt) + 1U).has_value());
    EXPECT_FALSE(common::ParseContextMode(0xFFU).has_value());
}

}  // namespace

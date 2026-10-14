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
/// RequiredKeyPermission() decides whether a key may bind: a type with no
/// permission, keyless or unknown, is refused. A keyed type missing from the
/// mapping would be refused outright; a keyless type wrongly given a permission
/// would accept a key it never uses. Neither mistake shows up in an integration
/// test, because the client only ever sends well-known type strings.

#include "score/crypto/src/daemon/common/context_types.hpp"
#include "score/crypto/src/daemon/common/context_mode.hpp"

#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/api/types/key.hpp"

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
    ctx::kKem,
    ctx::kKeyManagement,
};

/// Context types that bind no key at CTX_CREATE.
constexpr std::string_view kKeylessContextTypes[] = {
    ctx::kHash,
    ctx::kRandom,
    ctx::kKeyManagement,
};

TEST(ContextTypesTest, ExactlyTheKeyedTypesCarryAPermission)
{
    // A keyless type with a permission would accept a key it never uses; a keyed
    // type without one would be refused outright.
    for (const auto type : kAllContextTypes)
    {
        bool keyless = false;
        for (const auto keyless_type : kKeylessContextTypes)
        {
            keyless = keyless || (type == keyless_type);
        }
        const bool has_permission = common::RequiredKeyPermission(type, std::nullopt).has_value();

        EXPECT_NE(keyless, has_permission)
            << "context type '" << type << "' must carry a permission exactly when it binds a key";
    }
}

TEST(ContextTypesTest, UnknownTypeHasNoPermission)
{
    // The mediator refuses a key on any type without a permission, so an
    // unrecognised type cannot bind a key unchecked.
    EXPECT_FALSE(common::RequiredKeyPermission("NOT_A_CONTEXT_TYPE", std::nullopt).has_value());
    EXPECT_FALSE(common::RequiredKeyPermission("", std::nullopt).has_value());
}

TEST(ContextTypesTest, KeyedTypesDemandTheOperationTheyPerform)
{
    EXPECT_EQ(common::RequiredKeyPermission(ctx::kMac, std::nullopt), KeyOperationPermission::kMac);
    EXPECT_EQ(common::RequiredKeyPermission(ctx::kSign, std::nullopt), KeyOperationPermission::kSign);
    EXPECT_EQ(common::RequiredKeyPermission(ctx::kVerify, std::nullopt), KeyOperationPermission::kVerify);
    EXPECT_EQ(common::RequiredKeyPermission(ctx::kKem, std::nullopt), KeyOperationPermission::kAgree);
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

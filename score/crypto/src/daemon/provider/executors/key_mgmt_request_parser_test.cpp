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

#include "score/crypto/src/daemon/provider/executors/key_mgmt_request_parser.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <string_view>

namespace score::crypto::daemon::provider::crypto_executor::key_mgmt_request_parser
{
namespace
{
using Error = common::DaemonErrorCode;
using Permission = score::crypto::KeyOperationPermission;

constexpr std::string_view kAlgorithm{"ECDSA-P256"};
constexpr auto kSign = static_cast<std::uint32_t>(Permission::kSign);

class KeyMgmtRequestParserTest : public ::testing::Test
{
  protected:
    common::RequestParameters ImportParameters(common::RequestParameter permissions) const
    {
        return {kAlgorithm, permissions, static_cast<std::uint32_t>(score::crypto::FormatType::kRaw), key_data_};
    }

    const std::uint8_t key_bytes_[1U]{1U};
    const score::cpp::span<const std::uint8_t> key_data_{key_bytes_, 1U};
};

TEST_F(KeyMgmtRequestParserTest, GenerationDefaultsOnlyWhenPermissionsAreAbsent)
{
    const auto result = BuildGenerationRequest({kAlgorithm});

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().permissions, Permission::kAll);
    EXPECT_FALSE(result.value().public_key_permissions.has_value());
}

TEST_F(KeyMgmtRequestParserTest, GenerationPreservesPrivatePermissionsWhenPublicPermissionsAreAbsent)
{
    const auto result = BuildGenerationRequest({kAlgorithm, kSign});

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().permissions, Permission::kSign);
    EXPECT_FALSE(result.value().public_key_permissions.has_value());
}

class InvalidPermissionsTest : public KeyMgmtRequestParserTest,
                               public ::testing::WithParamInterface<common::RequestParameter>
{
};

TEST_P(InvalidPermissionsTest, GenerationRejectsInvalidPrivatePermissions)
{
    const auto result = BuildGenerationRequest({kAlgorithm, GetParam()});

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kInvalidArgument);
}

TEST_P(InvalidPermissionsTest, GenerationRejectsInvalidPublicPermissions)
{
    const auto result = BuildGenerationRequest({kAlgorithm, kSign, GetParam()});

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kInvalidArgument);
}

TEST_P(InvalidPermissionsTest, ImportRejectsInvalidPermissions)
{
    const auto result = BuildImportRequest(ImportParameters(GetParam()));

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kInvalidArgument);
}

INSTANTIATE_TEST_SUITE_P(WrongTypeOrUnknownBits,
                         InvalidPermissionsTest,
                         ::testing::Values(common::RequestParameter{common::NoParam{}},
                                           common::RequestParameter{true},
                                           common::RequestParameter{std::uint8_t{0x10U}},
                                           common::RequestParameter{std::uint16_t{0x10U}},
                                           common::RequestParameter{std::uint64_t{0x10U}},
                                           common::RequestParameter{std::string_view{"16"}},
                                           common::RequestParameter{std::uint32_t{0x0800U}},
                                           common::RequestParameter{std::uint32_t{0x0801U}},
                                           common::RequestParameter{std::uint32_t{0x80000000U}},
                                           common::RequestParameter{std::uint32_t{0xFFFFFFFFU}}));

class ValidPermissionsTest : public KeyMgmtRequestParserTest, public ::testing::WithParamInterface<Permission>
{
};

TEST_P(ValidPermissionsTest, GenerationPreservesExplicitPermissionsForBothKeyHalves)
{
    const auto permissions = static_cast<std::uint32_t>(GetParam());
    const auto result = BuildGenerationRequest({kAlgorithm, permissions, permissions});

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().permissions, GetParam());
    ASSERT_TRUE(result.value().public_key_permissions.has_value());
    EXPECT_EQ(result.value().public_key_permissions.value(), GetParam());
}

TEST_P(ValidPermissionsTest, ImportPreservesExplicitPermissions)
{
    const auto result = BuildImportRequest(ImportParameters(static_cast<std::uint32_t>(GetParam())));

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().permissions, GetParam());
}

INSTANTIATE_TEST_SUITE_P(DefinedMasks,
                         ValidPermissionsTest,
                         ::testing::Values(Permission::kNone,
                                           Permission::kAll,
                                           Permission::kSign,
                                           Permission::kSign | Permission::kExport | Permission::kImport));

}  // namespace
}  // namespace score::crypto::daemon::provider::crypto_executor::key_mgmt_request_parser

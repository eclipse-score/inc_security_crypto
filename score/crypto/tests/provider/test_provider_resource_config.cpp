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
#include "score/crypto/src/daemon/config/src/flatbuffer_config_parser.hpp"

#include <gtest/gtest.h>

#include <string_view>

namespace
{

namespace config = score::crypto::daemon::config;
using score::crypto::daemon::common::DaemonErrorCode;

constexpr std::string_view kMappingsPath = "score/crypto/tests/provider/config/provider_resource_test_config.bin";
constexpr std::string_view kEmptyNamePath =
    "score/crypto/tests/provider/config/provider_resource_empty_name_config.bin";
constexpr std::string_view kNoSectionPath = "score/crypto/tests/cert_management/config/cert_management_test_config.bin";

TEST(ProviderResourceConfigTest, ParsesMappingsInFileOrder)
{
    auto file = config::FlatBufferConfigParser::LoadFile(kMappingsPath);
    ASSERT_TRUE(file.has_value());
    config::ProviderResourceConfig parsed;

    const auto result = config::FlatBufferConfigParser::ParseProviderResourceConfig(file.value(), parsed);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result.value());

    const auto& mappings = parsed.GetAppProviderMappings();
    ASSERT_EQ(mappings.size(), 3U);
    EXPECT_EQ(mappings[0].uid, 1000U);
    EXPECT_EQ(mappings[0].app_resource_id, "app/sw");
    EXPECT_EQ(mappings[0].provider_name, "OPENSSL");
    EXPECT_EQ(mappings[1].app_resource_id, "app/hw");
    EXPECT_EQ(mappings[1].provider_name, "PKCS11_ENGINE");
    EXPECT_EQ(mappings[2].uid, 1001U);
    EXPECT_EQ(mappings[2].app_resource_id, "app/hw");
    EXPECT_EQ(mappings[2].provider_name, "OPENSSL");
}

TEST(ProviderResourceConfigTest, AbsentSectionIsNotAnError)
{
    auto file = config::FlatBufferConfigParser::LoadFile(kNoSectionPath);
    ASSERT_TRUE(file.has_value());
    config::ProviderResourceConfig parsed;

    const auto result = config::FlatBufferConfigParser::ParseProviderResourceConfig(file.value(), parsed);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result.value());
    EXPECT_TRUE(parsed.GetAppProviderMappings().empty());
}

TEST(ProviderResourceConfigTest, EmptyNameRejectsSectionAndLeavesOutputUnchanged)
{
    auto file = config::FlatBufferConfigParser::LoadFile(kEmptyNamePath);
    ASSERT_TRUE(file.has_value());
    config::ProviderResourceConfig parsed;
    parsed.AddAppProviderMapping({7U, "keep/me", "OPENSSL"});

    const auto result = config::FlatBufferConfigParser::ParseProviderResourceConfig(file.value(), parsed);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kInvalidArgument);
    ASSERT_EQ(parsed.GetAppProviderMappings().size(), 1U);
    EXPECT_EQ(parsed.GetAppProviderMappings()[0].app_resource_id, "keep/me");
}

}  // namespace

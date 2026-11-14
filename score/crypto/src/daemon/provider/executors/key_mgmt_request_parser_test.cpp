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

#include <array>
#include <cstdint>
#include <optional>

namespace
{
namespace ops = score::crypto::daemon::key_management::operations;
namespace parser = score::crypto::daemon::provider::crypto_executor::key_mgmt_request_parser;
using score::crypto::FormatType;
using score::crypto::daemon::common::DaemonErrorCode;
using score::crypto::daemon::common::RequestParameters;

TEST(FormatWireTest, EncodeDecode_RoundTrips)
{
    for (const auto& format : {std::optional<FormatType>{},
                               std::optional<FormatType>{FormatType::kDer},
                               std::optional<FormatType>{FormatType::kPem},
                               std::optional<FormatType>{FormatType::kRaw}})
    {
        std::optional<FormatType> decoded{FormatType::kPem};
        ASSERT_TRUE(ops::DecodeFormat(ops::EncodeFormat(format), decoded));
        EXPECT_EQ(decoded, format);
    }
    EXPECT_EQ(ops::EncodeFormat(std::nullopt), ops::kFormatNative);
}

TEST(FormatWireTest, Decode_OutOfRange_IsRejected)
{
    for (const std::uint32_t wire : {3U, 255U, 256U, 0xFFFFFFFEU})
    {
        std::optional<FormatType> decoded{FormatType::kPem};
        EXPECT_FALSE(ops::DecodeFormat(wire, decoded)) << wire;
        EXPECT_EQ(decoded, std::optional<FormatType>{FormatType::kPem}) << "Output must be left unchanged";
    }
}

TEST(FormatWireTest, ExtractOptionalFormat_AbsentOrSentinel_IsNative)
{
    const RequestParameters empty{};
    auto absent = parser::ExtractOptionalFormat(empty, 0U);
    ASSERT_TRUE(absent.has_value());
    EXPECT_FALSE(absent.value().has_value());

    const RequestParameters sentinel{ops::kFormatNative};
    auto native = parser::ExtractOptionalFormat(sentinel, 0U);
    ASSERT_TRUE(native.has_value());
    EXPECT_FALSE(native.value().has_value());

    const RequestParameters pem{static_cast<std::uint32_t>(FormatType::kPem)};
    auto explicit_pem = parser::ExtractOptionalFormat(pem, 0U);
    ASSERT_TRUE(explicit_pem.has_value());
    EXPECT_EQ(explicit_pem.value(), std::optional<FormatType>{FormatType::kPem});
}

TEST(FormatWireTest, ExtractOptionalFormat_BadValueOrType_IsInvalidArgument)
{
    for (const RequestParameters& request : {RequestParameters{std::uint32_t{256U}},
                                             RequestParameters{std::uint32_t{3U}},
                                             RequestParameters{std::uint64_t{0U}},
                                             RequestParameters{std::uint8_t{0U}}})
    {
        auto result = parser::ExtractOptionalFormat(request, 0U);
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error(), DaemonErrorCode::kInvalidArgument);
    }
}

TEST(FormatWireTest, BuildImportRequest_CarriesFormat)
{
    const std::array<std::uint8_t, 4U> key{1U, 2U, 3U, 4U};
    const score::cpp::span<const std::uint8_t> data{key.data(), key.size()};
    const std::uint32_t permissions = 0U;

    const RequestParameters native{std::string_view{"AES-256"}, permissions, ops::kFormatNative, data};
    auto native_req = parser::BuildImportRequest(native);
    ASSERT_TRUE(native_req.has_value());
    EXPECT_FALSE(native_req.value().format.has_value());
    EXPECT_EQ(native_req.value().key_data_size, key.size());

    const RequestParameters raw{
        std::string_view{"AES-256"}, permissions, static_cast<std::uint32_t>(FormatType::kRaw), data};
    auto raw_req = parser::BuildImportRequest(raw);
    ASSERT_TRUE(raw_req.has_value());
    EXPECT_EQ(raw_req.value().format, std::optional<FormatType>{FormatType::kRaw});

    const RequestParameters bad{std::string_view{"AES-256"}, permissions, std::uint32_t{256U}, data};
    auto bad_req = parser::BuildImportRequest(bad);
    ASSERT_FALSE(bad_req.has_value());
    EXPECT_EQ(bad_req.error(), DaemonErrorCode::kInvalidArgument);
}
}  // namespace

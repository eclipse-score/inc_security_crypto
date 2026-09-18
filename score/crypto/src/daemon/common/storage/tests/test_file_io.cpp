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

#include "score/crypto/src/daemon/common/storage/file_io.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>

namespace score::crypto::daemon::common::storage
{
namespace
{

std::filesystem::path TestPath(const std::string& suffix)
{
    return std::filesystem::temp_directory_path() /
           ("score_crypto_file_io_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) +
            "_" + suffix);
}

TEST(FileIoTest, MissingFileIsReportedAsAbsent)
{
    const auto path = TestPath("missing");

    const auto result = FileExists(path.string());

    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result.value());
}

TEST(FileIoTest, RegularFileIsReportedAsPresent)
{
    const auto path = TestPath("present");
    {
        std::ofstream output{path};
        ASSERT_TRUE(output.is_open());
        output << "data";
    }

    const auto result = FileExists(path.string());

    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result.value());
    std::filesystem::remove(path);
}

TEST(FileIoTest, MissingFileReadRetainsEmptyResourceMeaning)
{
    const auto path = TestPath("missing_read");

    const auto result = ReadFile(path.string(), 1024U);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kResourceNotAllocated);
}

TEST(FileIoTest, RemovingMissingFileIsIdempotent)
{
    const auto path = TestPath("missing_remove");

    const auto result = RemoveFile(path.string());

    EXPECT_TRUE(result.has_value());
}

}  // namespace
}  // namespace score::crypto::daemon::common::storage

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
           ("score_crypto_owner_only_file_io_" +
            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + "_" + suffix);
}

void CreateOwnerOnlyFile(const std::filesystem::path& path, const std::string& contents)
{
    std::ofstream output{path, std::ios::binary};
    ASSERT_TRUE(output.is_open());
    output << contents;
    output.close();
    std::filesystem::permissions(path,
                                 std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::replace);
}

TEST(OwnerOnlyFileIoTest, ReadsValidatedRegularFile)
{
    const auto path = TestPath("owner_only");
    CreateOwnerOnlyFile(path, "secret");

    const auto result = ReadOwnerOnlyFile(path.string(), 1024U);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(std::string(result->begin(), result->end()), "secret");
    std::filesystem::remove(path);
}

TEST(OwnerOnlyFileIoTest, RejectsGroupOrOtherPermissions)
{
    const auto path = TestPath("insecure_permissions");
    CreateOwnerOnlyFile(path, "secret");
    std::filesystem::permissions(path,
                                 std::filesystem::perms::owner_read | std::filesystem::perms::group_read,
                                 std::filesystem::perm_options::replace);

    const auto result = ReadOwnerOnlyFile(path.string(), 1024U);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kAccessDenied);
    std::filesystem::remove(path);
}

TEST(OwnerOnlyFileIoTest, RejectsSymbolicLink)
{
    const auto target_path = TestPath("symlink_target");
    const auto link_path = TestPath("symlink");
    CreateOwnerOnlyFile(target_path, "secret");
    std::filesystem::create_symlink(target_path, link_path);

    const auto result = ReadOwnerOnlyFile(link_path.string(), 1024U);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kAccessDenied);
    std::filesystem::remove(link_path);
    std::filesystem::remove(target_path);
}

TEST(OwnerOnlyFileIoTest, RejectsDirectory)
{
    const auto path = TestPath("directory");
    std::filesystem::create_directory(path);

    const auto result = ReadOwnerOnlyFile(path.string(), 1024U);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kAccessDenied);
    std::filesystem::remove(path);
}

TEST(OwnerOnlyFileIoTest, MapsMissingFileToResourceNotAllocated)
{
    const auto path = TestPath("missing");

    const auto result = ReadOwnerOnlyFile(path.string(), 1024U);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kResourceNotAllocated);
}

}  // namespace
}  // namespace score::crypto::daemon::common::storage

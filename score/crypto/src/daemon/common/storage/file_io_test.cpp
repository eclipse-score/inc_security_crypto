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

#include <sys/stat.h>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <system_error>
#include <vector>

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

/// Each SecureEraseFile test gets a private directory, removed again in TearDown even when an
/// assertion fails.
///
/// The directory lives under TEST_TMPDIR when the runner sets it. On QNX the default temporary
/// directory is /dev/shmem, which has no subdirectories, hard links or symbolic links; the QNX
/// test runner points TEST_TMPDIR at a full POSIX file system instead. Tests that need a link or
/// a named pipe skip themselves where the file system cannot create one.
class SecureEraseFileTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        const char* const test_tmpdir = std::getenv("TEST_TMPDIR");
        const std::filesystem::path root =
            (test_tmpdir != nullptr) ? std::filesystem::path{test_tmpdir} : std::filesystem::temp_directory_path();
        m_dir = root / ("score_crypto_secure_erase_" +
                        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::error_code error;
        ASSERT_TRUE(std::filesystem::create_directories(m_dir, error)) << error.message();
    }

    void TearDown() override
    {
        std::error_code ignored;
        std::filesystem::remove_all(m_dir, ignored);
    }

    [[nodiscard]] std::filesystem::path PathOf(const std::string& name) const
    {
        return m_dir / name;
    }

    static std::vector<char> ReadAll(const std::filesystem::path& path)
    {
        std::ifstream input{path, std::ios::binary};
        return {std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
    }

    static void WriteAll(const std::filesystem::path& path, const std::vector<char>& data)
    {
        std::ofstream output{path, std::ios::binary};
        output.write(data.data(), static_cast<std::streamsize>(data.size()));
    }

    static constexpr std::size_t kMaxSize = 64U * 1024U;

    std::filesystem::path m_dir;
};

TEST_F(SecureEraseFileTest, RemovesFile)
{
    const auto path = PathOf("key");
    WriteAll(path, std::vector<char>(32U, '\x5A'));

    const auto result = SecureEraseFile(path.string(), kMaxSize);

    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(std::filesystem::exists(path));
}

// A second hard link keeps the inode alive after the key file is unlinked, which makes the
// blocks the key file used observable. They must hold zeros, not the old key bytes.
TEST_F(SecureEraseFileTest, OverwritesContentInPlace)
{
    const auto path = PathOf("key");
    const auto link = PathOf("key.link");
    // Larger than one overwrite chunk and not a multiple of it.
    const std::vector<char> secret(10000U, '\x5A');
    WriteAll(path, secret);
    std::error_code error;
    std::filesystem::create_hard_link(path, link, error);
    if (error)
    {
        GTEST_SKIP() << "file system does not support hard links: " << error.message();
    }

    const auto result = SecureEraseFile(path.string(), kMaxSize);

    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(std::filesystem::exists(path));
    EXPECT_EQ(ReadAll(link), std::vector<char>(secret.size(), '\0'));
}

TEST_F(SecureEraseFileTest, MissingFileIsIdempotent)
{
    const auto result = SecureEraseFile(PathOf("missing").string(), kMaxSize);

    EXPECT_TRUE(result.has_value());
}

TEST_F(SecureEraseFileTest, RejectsEmptyPath)
{
    const auto result = SecureEraseFile("", kMaxSize);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kInvalidArgument);
}

TEST_F(SecureEraseFileTest, RejectsFileLargerThanLimit)
{
    const auto path = PathOf("large");
    const std::vector<char> data(65U, '\x5A');
    WriteAll(path, data);

    const auto result = SecureEraseFile(path.string(), 64U);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kInvalidArgument);
    EXPECT_EQ(ReadAll(path), data);
}

TEST_F(SecureEraseFileTest, DoesNotFollowSymbolicLink)
{
    const auto target = PathOf("target");
    const auto link = PathOf("link");
    const std::vector<char> data(16U, '\x5A');
    WriteAll(target, data);
    std::error_code error;
    std::filesystem::create_symlink(target, link, error);
    if (error)
    {
        GTEST_SKIP() << "file system does not support symbolic links: " << error.message();
    }

    const auto result = SecureEraseFile(link.string(), kMaxSize);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kInvalidArgument);
    EXPECT_EQ(ReadAll(target), data);
    EXPECT_TRUE(std::filesystem::is_symlink(link));
}

TEST_F(SecureEraseFileTest, RejectsDanglingSymbolicLink)
{
    const auto link = PathOf("dangling");
    std::error_code error;
    std::filesystem::create_symlink(PathOf("nowhere"), link, error);
    if (error)
    {
        GTEST_SKIP() << "file system does not support symbolic links: " << error.message();
    }

    const auto result = SecureEraseFile(link.string(), kMaxSize);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kInvalidArgument);
    EXPECT_TRUE(std::filesystem::is_symlink(link));
}

TEST_F(SecureEraseFileTest, RejectsDirectory)
{
    const auto path = PathOf("directory");
    std::error_code error;
    ASSERT_TRUE(std::filesystem::create_directory(path, error)) << error.message();

    const auto result = SecureEraseFile(path.string(), kMaxSize);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kInvalidArgument);
    EXPECT_TRUE(std::filesystem::exists(path));
}

// Without O_NONBLOCK, opening a named pipe for writing blocks until a reader appears, and this
// test would hang until the test timeout.
TEST_F(SecureEraseFileTest, RejectsNamedPipeWithoutBlocking)
{
    const auto path = PathOf("fifo");
    if (::mkfifo(path.c_str(), 0600) != 0)
    {
        GTEST_SKIP() << "file system does not support named pipes";
    }

    const auto result = SecureEraseFile(path.string(), kMaxSize);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kInvalidArgument);
    EXPECT_TRUE(std::filesystem::exists(path));
}

// CreateSecretFile shares the fixture: a private directory under TEST_TMPDIR.
using CreateSecretFileTest = SecureEraseFileTest;

score::crypto::span<const std::uint8_t> AsSpan(const std::vector<std::uint8_t>& data)
{
    return score::crypto::span<const std::uint8_t>{data.data(), data.size()};
}

TEST_F(CreateSecretFileTest, WritesOwnerOnlyFile)
{
    const auto path = PathOf("key");
    const std::vector<std::uint8_t> secret(32U, 0x5AU);

    const auto result = CreateSecretFile(path.string(), AsSpan(secret));

    ASSERT_TRUE(result.has_value());
    const auto read = ReadFile(path.string(), kMaxSize);
    ASSERT_TRUE(read.has_value());
    EXPECT_EQ(read.value(), secret);
    struct stat status{};
    ASSERT_EQ(::stat(path.c_str(), &status), 0);
    EXPECT_EQ(status.st_mode & 0777U, 0600U);
}

// Nothing but the key file is left behind: the temporary name is gone.
TEST_F(CreateSecretFileTest, LeavesNoTemporaryFile)
{
    const auto path = PathOf("key");

    ASSERT_TRUE(CreateSecretFile(path.string(), AsSpan(std::vector<std::uint8_t>(16U, 0x5AU))).has_value());

    std::vector<std::filesystem::path> entries;
    for (const auto& entry : std::filesystem::directory_iterator{m_dir})
    {
        entries.push_back(entry.path());
    }
    EXPECT_EQ(entries, std::vector<std::filesystem::path>{path});
}

TEST_F(CreateSecretFileTest, CreatesMissingParentDirectory)
{
    const auto path = PathOf("nested") / "key";

    const auto result = CreateSecretFile(path.string(), AsSpan(std::vector<std::uint8_t>(16U, 0x5AU)));

    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(std::filesystem::is_regular_file(path));
}

TEST_F(CreateSecretFileTest, ExistingFileIsNeverReplaced)
{
    const auto path = PathOf("key");
    const std::vector<char> existing(16U, '\x11');
    WriteAll(path, existing);

    const auto result = CreateSecretFile(path.string(), AsSpan(std::vector<std::uint8_t>(16U, 0x5AU)));

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kKeySlotOccupied);
    EXPECT_EQ(ReadAll(path), existing);
    std::size_t entries = 0U;
    for ([[maybe_unused]] const auto& entry : std::filesystem::directory_iterator{m_dir})
    {
        ++entries;
    }
    EXPECT_EQ(entries, 1U) << "the temporary file must be erased when the store is refused";
}

// A symbolic link at the key path counts as occupied; its target is never written.
TEST_F(CreateSecretFileTest, SymbolicLinkAtPathIsNotFollowed)
{
    const auto target = PathOf("target");
    const auto link = PathOf("key");
    const std::vector<char> data(16U, '\x11');
    WriteAll(target, data);
    std::error_code error;
    std::filesystem::create_symlink(target, link, error);
    if (error)
    {
        GTEST_SKIP() << "file system does not support symbolic links: " << error.message();
    }

    const auto result = CreateSecretFile(link.string(), AsSpan(std::vector<std::uint8_t>(16U, 0x5AU)));

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kKeySlotOccupied);
    EXPECT_EQ(ReadAll(target), data);
}

TEST_F(CreateSecretFileTest, RejectsEmptyPathOrData)
{
    const std::vector<std::uint8_t> secret(16U, 0x5AU);

    const auto no_path = CreateSecretFile("", AsSpan(secret));
    const auto no_data = CreateSecretFile(PathOf("key").string(), AsSpan(std::vector<std::uint8_t>{}));

    ASSERT_FALSE(no_path.has_value());
    EXPECT_EQ(no_path.error(), DaemonErrorCode::kInvalidArgument);
    ASSERT_FALSE(no_data.has_value());
    EXPECT_EQ(no_data.error(), DaemonErrorCode::kInvalidArgument);
    EXPECT_FALSE(std::filesystem::exists(PathOf("key")));
}

}  // namespace
}  // namespace score::crypto::daemon::common::storage

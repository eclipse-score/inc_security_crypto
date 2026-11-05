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

/// @file test_file_backed_slot_handler.cpp
/// @brief Tests for key slot deletion in FileBackedSlotHandler.
///
/// Each test builds a real deployment descriptor and key file in a private
/// temporary directory, so ClearSlot runs against the file system exactly as it
/// does in the daemon. The directory lives under TEST_TMPDIR when the runner sets
/// it: on QNX the default temporary directory is /dev/shmem, which has no
/// subdirectories or links. Tests that need a link skip themselves where the file
/// system cannot create one.

#include "score/crypto/src/daemon/key_management/slot/file_backed_slot_handler.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <system_error>
#include <vector>

namespace km = score::crypto::daemon::key_management;
using score::crypto::KeySlotState;
using score::crypto::daemon::common::DaemonErrorCode;

namespace
{

class FileBackedSlotHandlerClearSlotTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        const char* const test_tmpdir = std::getenv("TEST_TMPDIR");
        const std::filesystem::path root =
            (test_tmpdir != nullptr) ? std::filesystem::path{test_tmpdir} : std::filesystem::temp_directory_path();
        m_dir = root / ("score_crypto_key_slot_" +
                        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::error_code error;
        ASSERT_TRUE(std::filesystem::create_directories(m_dir, error)) << error.message();
        m_key_path = m_dir / "slot.key";
        m_descriptor_path = m_dir / "slot.kv";

        m_slot.slot_name = "test/hmac-256";
        m_slot.algorithm = "HMAC-SHA256";
        m_slot.deployment_path = m_descriptor_path.string();
        m_slot.deployment_format = "kv";

        // ClearSlot and GetSlotState never call the key factory, so none is needed.
        m_handler = std::make_shared<km::FileBackedSlotHandler>(nullptr);
    }

    void TearDown() override
    {
        std::error_code ignored;
        std::filesystem::remove_all(m_dir, ignored);
    }

    void WriteDescriptor() const
    {
        std::ofstream descriptor{m_descriptor_path};
        descriptor << "[metadata]\navailability=active\n[key]\nkey_path=" << m_key_path.string()
                   << "\nkey_format=raw\n";
    }

    void WriteKey() const
    {
        std::ofstream key{m_key_path, std::ios::binary};
        key.write(kKey.data(), static_cast<std::streamsize>(kKey.size()));
    }

    static std::vector<char> ReadAll(const std::filesystem::path& path)
    {
        std::ifstream input{path, std::ios::binary};
        return {std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
    }

    const std::vector<char> kKey = std::vector<char>(32U, '\x5A');

    std::filesystem::path m_dir;
    std::filesystem::path m_key_path;
    std::filesystem::path m_descriptor_path;
    km::KeySlotConfig m_slot{};
    std::shared_ptr<km::FileBackedSlotHandler> m_handler;
};

TEST_F(FileBackedSlotHandlerClearSlotTest, OccupiedSlot_IsEmptyAfterClear)
{
    WriteDescriptor();
    WriteKey();
    ASSERT_EQ(m_handler->GetSlotState(m_slot).value(), KeySlotState::kOccupied);

    const auto result = m_handler->ClearSlot(m_slot);

    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(std::filesystem::exists(m_key_path));
    EXPECT_EQ(m_handler->GetSlotState(m_slot).value(), KeySlotState::kEmpty);
}

// A second hard link keeps the key file's inode alive after ClearSlot unlinks it,
// which makes the blocks that held the key observable: they must hold zeros.
TEST_F(FileBackedSlotHandlerClearSlotTest, KeyFileIsOverwrittenBeforeRemoval)
{
    WriteDescriptor();
    WriteKey();
    const auto link = m_dir / "slot.key.link";
    std::error_code error;
    std::filesystem::create_hard_link(m_key_path, link, error);
    if (error)
    {
        GTEST_SKIP() << "file system does not support hard links: " << error.message();
    }

    const auto result = m_handler->ClearSlot(m_slot);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(ReadAll(link), std::vector<char>(kKey.size(), '\0'));
}

// The descriptor keeps key_path so a future StoreKey can write to the same location.
TEST_F(FileBackedSlotHandlerClearSlotTest, DeploymentDescriptorIsKept)
{
    WriteDescriptor();
    WriteKey();

    ASSERT_TRUE(m_handler->ClearSlot(m_slot).has_value());

    EXPECT_TRUE(std::filesystem::exists(m_descriptor_path));
}

TEST_F(FileBackedSlotHandlerClearSlotTest, LoadAfterClear_ReportsEmptySlot)
{
    WriteDescriptor();
    WriteKey();
    ASSERT_TRUE(m_handler->ClearSlot(m_slot).has_value());

    const auto load = m_handler->LoadKey(m_slot);

    ASSERT_FALSE(load.has_value());
    EXPECT_EQ(load.error(), DaemonErrorCode::kKeySlotEmpty);
}

TEST_F(FileBackedSlotHandlerClearSlotTest, ClearingTwice_IsIdempotent)
{
    WriteDescriptor();
    WriteKey();
    ASSERT_TRUE(m_handler->ClearSlot(m_slot).has_value());

    const auto second = m_handler->ClearSlot(m_slot);

    EXPECT_TRUE(second.has_value());
    EXPECT_EQ(m_handler->GetSlotState(m_slot).value(), KeySlotState::kEmpty);
}

TEST_F(FileBackedSlotHandlerClearSlotTest, MissingDeploymentDescriptor_IsAlreadyEmpty)
{
    const auto result = m_handler->ClearSlot(m_slot);

    EXPECT_TRUE(result.has_value());
}

TEST_F(FileBackedSlotHandlerClearSlotTest, UnsafeDeploymentPath_IsRejected)
{
    m_slot.deployment_path = "relative/slot.kv";

    const auto result = m_handler->ClearSlot(m_slot);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kInvalidArgument);
}

// A symbolic link in place of the key file is refused, and its target is left untouched.
TEST_F(FileBackedSlotHandlerClearSlotTest, SymbolicLinkAsKeyFile_IsRefused)
{
    WriteDescriptor();
    const auto target = m_dir / "other.key";
    {
        std::ofstream other{target, std::ios::binary};
        other.write(kKey.data(), static_cast<std::streamsize>(kKey.size()));
    }
    std::error_code error;
    std::filesystem::create_symlink(target, m_key_path, error);
    if (error)
    {
        GTEST_SKIP() << "file system does not support symbolic links: " << error.message();
    }

    const auto result = m_handler->ClearSlot(m_slot);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kInvalidArgument);
    EXPECT_EQ(ReadAll(target), kKey);
}

// The erase is permanent, so a relative key_path is refused rather than resolved against
// the daemon's working directory.
TEST_F(FileBackedSlotHandlerClearSlotTest, RelativeKeyPath_IsRejected)
{
    {
        std::ofstream descriptor{m_descriptor_path};
        descriptor << "[key]\nkey_path=slot.key\nkey_format=raw\n";
    }

    const auto result = m_handler->ClearSlot(m_slot);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kInvalidArgument);
}

TEST_F(FileBackedSlotHandlerClearSlotTest, KeyPathWithTraversal_IsRejected)
{
    WriteKey();
    {
        std::ofstream descriptor{m_descriptor_path};
        descriptor << "[key]\nkey_path=" << (m_dir / ".." / m_dir.filename() / "slot.key").string()
                   << "\nkey_format=raw\n";
    }

    const auto result = m_handler->ClearSlot(m_slot);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kInvalidArgument);
    EXPECT_EQ(ReadAll(m_key_path), kKey);
}

// A key_path that names a file larger than any key file is refused, so a misconfigured
// descriptor cannot destroy an unrelated file.
TEST_F(FileBackedSlotHandlerClearSlotTest, OversizedKeyFile_IsRefused)
{
    WriteDescriptor();
    const std::vector<char> large(8U * 1024U + 1U, '\x5A');
    {
        std::ofstream key{m_key_path, std::ios::binary};
        key.write(large.data(), static_cast<std::streamsize>(large.size()));
    }

    const auto result = m_handler->ClearSlot(m_slot);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kInvalidArgument);
    EXPECT_EQ(ReadAll(m_key_path), large);
}

}  // namespace

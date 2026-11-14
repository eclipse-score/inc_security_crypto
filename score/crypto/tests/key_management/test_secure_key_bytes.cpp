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

/// @file test_secure_key_bytes.cpp
/// @brief Tests for the zeroization of temporary key buffers (SecureKeyBytes).

#include "score/crypto/src/daemon/key_management/interfaces/key_types.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace km = score::crypto::daemon::key_management;

namespace
{

constexpr std::size_t kKeySize = 32U;
constexpr std::uint8_t kKeyByte = 0x5AU;

km::SecureKeyBytes MakeKey()
{
    km::SecureKeyBytes key{kKeySize};
    for (auto& byte : key.bytes)
    {
        byte = kKeyByte;
    }
    return key;
}

// Zeroize() keeps the size, so the zeroed bytes can be checked within bounds.
TEST(SecureKeyBytesTest, Zeroize_ZeroizesEveryByteInPlace)
{
    auto key = MakeKey();

    key.Zeroize();

    EXPECT_EQ(key.bytes, std::vector<std::uint8_t>(kKeySize, 0U));
}

// Wipe() is Zeroize() followed by clear(); the zeroing itself is checked above.
TEST(SecureKeyBytesTest, Wipe_LeavesBufferEmpty)
{
    auto key = MakeKey();

    key.Wipe();

    EXPECT_TRUE(key.bytes.empty());
}

TEST(SecureKeyBytesTest, Wipe_OnEmptyBuffer_IsHarmless)
{
    km::SecureKeyBytes key{};

    key.Wipe();

    EXPECT_TRUE(key.bytes.empty());
}

TEST(SecureKeyBytesTest, MoveAssignment_TakesSourceBytes)
{
    auto target = MakeKey();
    km::SecureKeyBytes source{4U};
    source.bytes = {1U, 2U, 3U, 4U};

    target = std::move(source);

    EXPECT_EQ(target.bytes, (std::vector<std::uint8_t>{1U, 2U, 3U, 4U}));
}

TEST(SecureKeyBytesTest, MoveConstruction_TransfersBytes)
{
    auto source = MakeKey();

    km::SecureKeyBytes moved{std::move(source)};

    EXPECT_EQ(moved.bytes, std::vector<std::uint8_t>(kKeySize, kKeyByte));
}

}  // namespace

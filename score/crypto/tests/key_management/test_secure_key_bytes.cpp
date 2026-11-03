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

// Wipe() keeps the vector's capacity, so its storage stays owned by the vector
// and can be inspected after the wipe. That read is past size(), so a build with
// container-overflow checks (_GLIBCXX_SANITIZE_VECTOR under ASan, or libc++'s
// annotations) would report it; such a build has to exclude this test.
TEST(SecureKeyBytesTest, Wipe_ZeroizesBufferAndClearsIt)
{
    auto key = MakeKey();
    const std::uint8_t* const storage = key.bytes.data();

    key.Wipe();

    EXPECT_TRUE(key.bytes.empty());
    ASSERT_GE(key.bytes.capacity(), kKeySize);
    ASSERT_EQ(key.bytes.data(), storage);
    for (std::size_t i = 0U; i < kKeySize; ++i)
    {
        EXPECT_EQ(storage[i], 0U) << "byte " << i << " still holds key material";
    }
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

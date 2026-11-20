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

#include "score/crypto/src/daemon/common/context/keyed_registry.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

namespace score::crypto::daemon::common
{
namespace
{

class Entry
{
  public:
    virtual ~Entry() = default;
    [[nodiscard]] virtual int Value() const noexcept = 0;
};

class FixedEntry final : public Entry
{
  public:
    explicit FixedEntry(const int value) : m_value{value} {}
    [[nodiscard]] int Value() const noexcept override
    {
        return m_value;
    }

  private:
    int m_value;
};

enum class Kind : std::uint8_t
{
    kFirst,
    kSecond,
};

TEST(KeyedRegistryTest, RegisteredEntryIsFoundByKey)
{
    KeyedRegistry<std::string, Entry> registry;
    auto entry = std::make_shared<FixedEntry>(11);
    ASSERT_TRUE(registry.Register("HASH", entry));

    const auto found = registry.Find(std::string{"HASH"});
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found, entry);
    EXPECT_EQ(found->Value(), 11);
    EXPECT_EQ(registry.Size(), 1U);
}

TEST(KeyedRegistryTest, UnregisteredKeyReturnsNull)
{
    KeyedRegistry<std::string, Entry> registry;
    ASSERT_TRUE(registry.Register("HASH", std::make_shared<FixedEntry>(1)));

    EXPECT_EQ(registry.Find(std::string{"SIGN"}), nullptr);
    EXPECT_EQ(registry.Find(std::string_view{"SIGN"}), nullptr);
}

TEST(KeyedRegistryTest, EmptyRegistryReturnsNullAndHasSizeZero)
{
    KeyedRegistry<std::string, Entry> registry;

    EXPECT_EQ(registry.Size(), 0U);
    EXPECT_EQ(registry.Find(std::string{"HASH"}), nullptr);
}

TEST(KeyedRegistryTest, DuplicateKeyIsRejectedAndFirstEntryIsKept)
{
    KeyedRegistry<std::string, Entry> registry;
    auto first = std::make_shared<FixedEntry>(1);
    ASSERT_TRUE(registry.Register("HASH", first));

    EXPECT_FALSE(registry.Register("HASH", std::make_shared<FixedEntry>(2)));

    EXPECT_EQ(registry.Size(), 1U);
    const auto found = registry.Find(std::string{"HASH"});
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found, first);
    EXPECT_EQ(found->Value(), 1);
}

TEST(KeyedRegistryTest, NullEntryIsRejected)
{
    KeyedRegistry<std::string, Entry> registry;

    EXPECT_FALSE(registry.Register("HASH", nullptr));

    EXPECT_EQ(registry.Size(), 0U);
    EXPECT_EQ(registry.Find(std::string{"HASH"}), nullptr);
}

TEST(KeyedRegistryTest, StringRegistryIsSearchableByStringView)
{
    KeyedRegistry<std::string, Entry> registry;
    auto entry = std::make_shared<FixedEntry>(5);
    ASSERT_TRUE(registry.Register("CERT:VERIFICATION", entry));

    const std::string_view key{"CERT:VERIFICATION"};
    EXPECT_EQ(registry.Find(key), entry);
}

TEST(KeyedRegistryTest, EnumKeyIsSupported)
{
    KeyedRegistry<Kind, Entry> registry;
    auto first = std::make_shared<FixedEntry>(1);
    auto second = std::make_shared<FixedEntry>(2);
    ASSERT_TRUE(registry.Register(Kind::kFirst, first));
    ASSERT_TRUE(registry.Register(Kind::kSecond, second));

    EXPECT_EQ(registry.Find(Kind::kFirst), first);
    EXPECT_EQ(registry.Find(Kind::kSecond), second);
    EXPECT_EQ(registry.Size(), 2U);
}

}  // namespace
}  // namespace score::crypto::daemon::common

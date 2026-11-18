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

#include "score/crypto/src/daemon/key_management/core/key_entry.hpp"

#include <gtest/gtest.h>

#include <memory>
#include <variant>

namespace km = score::crypto::daemon::key_management;
namespace common = score::crypto::daemon::common;
namespace data_manager = score::crypto::daemon::data_manager;

namespace
{

class TestKeyHandler final : public km::IKeyHandler
{
  public:
    const km::ProviderKeyHandle& GetHandle() const noexcept override
    {
        return m_handle;
    }

    common::ProviderId GetProviderId() const noexcept override
    {
        return m_handle.provider_id;
    }

    score::crypto::Expected<std::monostate, common::DaemonErrorCode> Release() override
    {
        return std::monostate{};
    }

    score::crypto::Expected<km::SecureKeyBytes, common::DaemonErrorCode> Export() const override
    {
        return km::SecureKeyBytes{};
    }

  private:
    km::ProviderKeyHandle m_handle{};
};

}  // namespace

TEST(KeyEntryTest, ReleasingUnknownClientDoesNotDecrementRefCount)
{
    const data_manager::ClientId tracked_client_id{1U};
    const data_manager::ClientId unknown_client_id{2U};
    const auto key_entry =
        std::make_shared<km::KeyEntry>(std::make_shared<TestKeyHandler>(), common::kInvalidProviderId);

    key_entry->AddRef(tracked_client_id);
    EXPECT_EQ(key_entry->GetRefCount(), 1U);

    EXPECT_FALSE(key_entry->Release(unknown_client_id));
    EXPECT_EQ(key_entry->GetRefCount(), 1U);

    EXPECT_TRUE(key_entry->Release(tracked_client_id));
    EXPECT_EQ(key_entry->GetRefCount(), 0U);
}

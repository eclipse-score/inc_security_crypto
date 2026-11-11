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

#include "score/crypto/src/api/data_plane/src/shm_memory_allocator.hpp"

#include "score/crypto/src/api/control_plane/i_connection.hpp"
#include "score/crypto/src/api/data_plane/i_read_write_memory_factory.hpp"
#include "score/crypto/src/api/data_plane/i_shm_region_registry.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

namespace score::crypto
{
namespace
{

namespace protocol = daemon::control_plane::protocol;
namespace mediator_operations = daemon::mediator::operations;

class RecordingConnection final : public api::control_plane::IConnection
{
  public:
    Expected<protocol::ControlResponse, CryptoErrorCode> SendRequest(const protocol::ControlRequest& request) override
    {
        requests.push_back(request);
        return make_unexpected(CryptoErrorCode::kConnectionFailed);
    }

    protocol::DataNodeId GetConnectionNodeId() const override
    {
        return 7U;
    }

    std::vector<protocol::ControlRequest> requests;
};

class UnusedMemoryFactory final : public IReadWriteMemoryFactory
{
  public:
    Expected<ShmCreateResult, CryptoErrorCode> Create(const ShmRegionParams& /*region_params*/) override
    {
        return make_unexpected(CryptoErrorCode::kAllocationFailed);
    }
};

class EmptyRegionRegistry final : public IShmRegionRegistry
{
  public:
    void Register(const RegionEntry& /*entry*/) override {}

    void Unregister(std::uint64_t /*node_id*/) override {}

    std::uint64_t IdentifyNode(score::cpp::span<const std::uint8_t> /*data*/) const noexcept override
    {
        return 0U;
    }

    Expected<std::size_t, CryptoErrorCode> GetOffset(
        score::cpp::span<const std::uint8_t> /*data*/) const noexcept override
    {
        return make_unexpected(CryptoErrorCode::kInvalidMemoryRegion);
    }

    std::size_t GetTotalRegisteredSize() const noexcept override
    {
        return 0U;
    }

    std::size_t GetQuota() const noexcept override
    {
        return 0U;
    }
};

class ShmMemoryAllocatorProviderHintTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        connection_ = std::make_shared<RecordingConnection>();
        auto allocator = ShmMemoryAllocator::Create(
            connection_, std::make_shared<UnusedMemoryFactory>(), std::make_shared<EmptyRegionRegistry>());
        ASSERT_TRUE(allocator.has_value());
        allocator_ = std::move(allocator.value());
    }

    void ExpectProviderHint(const std::uint16_t resource_provider, const std::uint64_t expected_wire_provider)
    {
        CryptoResourceId resource{};
        resource.primary_provider = resource_provider;

        EXPECT_FALSE(allocator_->Allocate(64U, resource).has_value());
        ASSERT_EQ(connection_->requests.size(), 1U);
        ASSERT_EQ(connection_->requests.front().operation.operations.size(), 1U);
        const auto provider_parameter =
            connection_->requests.front().operation.operations.front().getParameter<std::uint64_t>(2U);
        ASSERT_TRUE(provider_parameter.has_value());
        EXPECT_EQ(provider_parameter.value(), expected_wire_provider);
    }

    std::shared_ptr<RecordingConnection> connection_;
    std::unique_ptr<ShmMemoryAllocator> allocator_;
};

TEST_F(ShmMemoryAllocatorProviderHintTest, ForwardsZeroAsAValidProviderId)
{
    ExpectProviderHint(0U, 0U);
}

TEST_F(ShmMemoryAllocatorProviderHintTest, EncodesUnboundResourceWithInvalidProviderSentinel)
{
    ExpectProviderHint(kUnboundProviderId, mediator_operations::SHM_WIRE_PROVIDER_ID_UNBOUND);
}

TEST_F(ShmMemoryAllocatorProviderHintTest, ForwardsNonzeroProviderId)
{
    ExpectProviderHint(42U, 42U);
}

}  // namespace
}  // namespace score::crypto

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

#include "score/crypto/src/daemon/mediator/src/mediator_impl.hpp"

#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/daemon/config/inc/config.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/data_manager/data_manager.hpp"
#include "score/crypto/src/daemon/key_management/core/key_management_service.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_slot_config.hpp"
#include "score/crypto/src/daemon/key_management/slot/slot_registry.hpp"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"
#include "score/crypto/src/daemon/provider/provider_manager.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace score::crypto::daemon::mediator
{
namespace
{

namespace protocol = control_plane::protocol;

class MediatorResourceResolutionTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        data_manager_ = std::make_shared<data_manager::DataManager>();
        slot_registry_ = std::make_shared<key_management::SlotRegistry>();
        provider_manager_ = std::make_shared<provider::ProviderManager>(config::ProviderInitConfig{});
        key_management_service_ =
            std::make_shared<key_management::KeyManagementService>(data_manager_, provider_manager_, slot_registry_);
        mediator_ = std::make_unique<MediatorImpl>(
            MediatorDependencies{data_manager_, provider_manager_, key_management_service_, nullptr});
    }

    void RegisterSlot(std::vector<common::ProviderId> provider_ids)
    {
        key_management::KeySlotConfig config{};
        config.slot_name = kSlotName;
        config.provider_ids = std::move(provider_ids);
        config.access_policy.allowed_uids = {kUid};
        const auto slot_handle = slot_registry_->RegisterSlot(std::move(config));
        ASSERT_TRUE(slot_handle.IsValid());
        slot_registry_->RegisterAppResource(kUid, kResourceName, kSlotName);
    }

    control_plane::ControlResponse ResolveSlot()
    {
        auto operation = protocol::OperationRequestBuilder()
                             .operation(operations::ResolveResource())
                             .with_in_string(kResourceName)
                             .with_in_val_uint64(static_cast<std::uint64_t>(ResourceType::kKeySlot))
                             .build();
        EXPECT_TRUE(operation.has_value());

        control_plane::ControlRequest request{};
        request.request_id = 1U;
        request.pid = kPid;
        request.uid = kUid;
        request.data_node_id = 0U;
        if (operation.has_value())
        {
            request.operation = std::move(operation.value());
        }
        return mediator_->processRequest(request);
    }

    static constexpr std::uint32_t kPid{42U};
    static constexpr std::uint32_t kUid{1000U};
    static constexpr char kResourceName[]{"application-key"};
    static constexpr char kSlotName[]{"slot/application-key"};

    std::shared_ptr<data_manager::DataManager> data_manager_;
    std::shared_ptr<key_management::SlotRegistry> slot_registry_;
    provider::ProviderManager::Sptr provider_manager_;
    key_management::KeyManagementService::Sptr key_management_service_;
    std::unique_ptr<MediatorImpl> mediator_;
};

TEST_F(MediatorResourceResolutionTest, ReturnsResolvedPrimaryProviderAndPersistentLifetime)
{
    constexpr common::ProviderId kPrimaryProvider{42U};
    RegisterSlot({kPrimaryProvider});

    const auto response = ResolveSlot();

    ASSERT_EQ(response.operation.operations.size(), 1U);
    const auto& operation = response.operation.operations.front();
    const auto resource_type = operation.getParameter<std::uint8_t>(1U);
    const auto is_persistent = operation.getParameter<bool>(2U);
    const auto provider_id = operation.getParameter<std::uint16_t>(3U);

    EXPECT_EQ(operation.result, protocol::OPERATION_RESULT_SUCCESS);
    ASSERT_TRUE(resource_type.has_value());
    ASSERT_TRUE(is_persistent.has_value());
    ASSERT_TRUE(provider_id.has_value());
    EXPECT_EQ(resource_type.value(), static_cast<std::uint8_t>(ResourceType::kKeySlot));
    EXPECT_TRUE(is_persistent.value());
    EXPECT_EQ(provider_id.value(), kPrimaryProvider);
}

TEST_F(MediatorResourceResolutionTest, PreservesProviderZeroAsAResolvedPrimaryProvider)
{
    RegisterSlot({0U});

    const auto response = ResolveSlot();

    ASSERT_EQ(response.operation.operations.size(), 1U);
    const auto& operation = response.operation.operations.front();
    const auto provider_id = operation.getParameter<std::uint16_t>(3U);

    EXPECT_EQ(operation.result, protocol::OPERATION_RESULT_SUCCESS);
    ASSERT_TRUE(provider_id.has_value());
    EXPECT_EQ(provider_id.value(), 0U);
}

TEST_F(MediatorResourceResolutionTest, KeepsResolutionSuccessfulWhenSlotHasNoPrimaryProvider)
{
    RegisterSlot({});

    const auto response = ResolveSlot();

    ASSERT_EQ(response.operation.operations.size(), 1U);
    const auto& operation = response.operation.operations.front();
    const auto provider_id = operation.getParameter<std::uint16_t>(3U);

    EXPECT_EQ(operation.result, protocol::OPERATION_RESULT_SUCCESS);
    ASSERT_TRUE(provider_id.has_value());
    EXPECT_EQ(provider_id.value(), common::kInvalidProviderId);
}

}  // namespace
}  // namespace score::crypto::daemon::mediator

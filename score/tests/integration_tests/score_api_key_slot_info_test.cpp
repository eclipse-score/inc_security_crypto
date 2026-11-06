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

/// @file score_api_key_slot_info_test.cpp
/// @brief End-to-end checks for IKeyManagementContext::GetKeySlotInfo().
///
/// The expected values come from the slot entries in
/// score/tests/test_vectors/config/integration_test_config.json.

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/config/key_management_context_config.hpp"
#include "score/crypto/src/api/config/key_operation_params.hpp"
#include "score/crypto/src/api/contexts/i_key_management_context.hpp"
#include "score/crypto/src/api/crypto_stack_factory.hpp"
#include "score/crypto/src/api/i_crypto_context.hpp"
#include "score/crypto/src/api/i_crypto_stack.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/api/types/key.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

using namespace score::crypto;

namespace
{

#ifdef __QNXNTO__
constexpr auto kControlSocketEndpoint = "unix:///opt/crypto_daemon.sock";
#else
constexpr auto kControlSocketEndpoint = "unix:///tmp/crypto_daemon.sock";
#endif

class KeySlotInfoTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        CryptoStackConfig stack_config;
        stack_config.SetConnectionEndpoint(kControlSocketEndpoint);

        auto stack_result = CreateCryptoStack(stack_config);
        ASSERT_TRUE(stack_result.has_value()) << "Failed to create crypto stack";
        stack_ = std::move(stack_result.value());

        auto ctx_result = stack_->CreateCryptoContext();
        ASSERT_TRUE(ctx_result.has_value()) << "Failed to create crypto context";
        ctx_ = std::move(ctx_result.value());

        KeyManagementContextConfig key_mgmt_config;
        key_mgmt_config.SetProviderType(ProviderType::kSoftware);
        auto key_mgmt_result = ctx_->CreateKeyManagementContext(key_mgmt_config);
        ASSERT_TRUE(key_mgmt_result.has_value()) << "Failed to create key management context";
        key_mgmt_ = std::move(key_mgmt_result.value());
    }

    CryptoResourceId ResolveSlot(const std::string& name)
    {
        auto slot_result = ctx_->ResolveResource(name, ResourceType::kKeySlot);
        EXPECT_TRUE(slot_result.has_value()) << "Failed to resolve slot " << name;
        return slot_result.has_value() ? slot_result.value() : CryptoResourceId{};
    }

    // The daemon reports the provider that owns a generated key; every slot in
    // this test is bound to the same software (OpenSSL) provider.
    std::uint16_t SoftwareProviderId()
    {
        GenerateKeyParams params;
        params.SetAlgorithm("HMAC-SHA256").SetPermissions(KeyOperationPermission::kMac);
        auto key_result = key_mgmt_->GenerateKey(params);
        EXPECT_TRUE(key_result.has_value()) << "Failed to generate reference key";
        return key_result.has_value() ? key_result.value().Id().primary_provider : 0U;
    }

    void ExpectSlotInfo(const std::string& slot_name, std::string_view algorithm, KeyOperationPermission permissions)
    {
        const auto slot = ResolveSlot(slot_name);
        auto info_result = key_mgmt_->GetKeySlotInfo(slot);
        ASSERT_TRUE(info_result.has_value()) << "GetKeySlotInfo failed for " << slot_name;
        const auto& info = info_result.value();

        EXPECT_EQ(info.state, KeySlotState::kOccupied) << slot_name;
        EXPECT_EQ(std::string_view{info.algorithm}, algorithm) << slot_name;
        EXPECT_EQ(info.permitted_operations, permissions) << slot_name;
        EXPECT_EQ(info.primary_provider, SoftwareProviderId()) << slot_name;
        EXPECT_EQ(info.compatible_provider_count, 0U) << slot_name;
    }

    std::unique_ptr<IKeyManagementContext> MakeKeyManagement(ProviderType provider)
    {
        KeyManagementContextConfig config;
        config.SetProviderType(provider);
        auto result = ctx_->CreateKeyManagementContext(config);
        EXPECT_TRUE(result.has_value()) << "Failed to create key management context";
        return result.has_value() ? std::move(result.value()) : nullptr;
    }

    ICryptoStack::Uptr stack_;
    ICryptoContext::Uptr ctx_;
    std::unique_ptr<IKeyManagementContext> key_mgmt_;
};

TEST_F(KeySlotInfoTest, MacSlot_ReportsConfiguredMetadata)
{
    ExpectSlotInfo("HMAC_SHA256_IntegrationTestKey_OpenSSL", "HMAC-SHA256", KeyOperationPermission::kMac);
}

TEST_F(KeySlotInfoTest, CipherSlot_ReportsConfiguredMetadata)
{
    ExpectSlotInfo("AES128_CBC_IntegrationTestKey_OpenSSL",
                   "AES-128-CBC",
                   KeyOperationPermission::kEncrypt | KeyOperationPermission::kDecrypt);
}

TEST_F(KeySlotInfoTest, SigningSlot_ReportsConfiguredMetadata)
{
    ExpectSlotInfo("ECDSA_P256_IntegrationTestKey_OpenSSL",
                   "ECDSA-P256",
                   KeyOperationPermission::kSign | KeyOperationPermission::kVerify);
}

TEST_F(KeySlotInfoTest, PublicKeySlot_ReportsVerifyOnly)
{
    ExpectSlotInfo("ECDSA_P256_PublicKeySlot_OpenSSL", "ECDSA-P256", KeyOperationPermission::kVerify);
}

TEST_F(KeySlotInfoTest, KeyHandleInsteadOfSlot_IsRejected)
{
    CryptoResourceId not_a_slot{};
    not_a_slot.id = ResolveSlot("HMAC_SHA256_IntegrationTestKey_OpenSSL").id;
    not_a_slot.type = ResourceType::kKey;

    auto info_result = key_mgmt_->GetKeySlotInfo(not_a_slot);
    ASSERT_FALSE(info_result.has_value());
    EXPECT_EQ(*info_result.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kInvalidArgument));
}

TEST_F(KeySlotInfoTest, UnknownSlotId_IsRejected)
{
    CryptoResourceId unknown{};
    unknown.id = std::numeric_limits<std::uint64_t>::max();
    unknown.type = ResourceType::kKeySlot;

    EXPECT_FALSE(key_mgmt_->GetKeySlotInfo(unknown).has_value());
}

#ifdef SCORE_CRYPTO_HARDWARE_BACKEND_ENABLED
// A key-management context may be served by a provider other than the slot's
// primary provider. Each provider reads only its own entries of a slot's
// deployment file, so the slot must be queried through its owner; asking the
// context's provider would report an occupied slot as empty.
constexpr auto kOpenSslSlot = "HMAC_SHA256_IntegrationTestKey_OpenSSL";
constexpr auto kPkcs11Slot = "HMAC_SHA256_IntegrationTestKey";

TEST_F(KeySlotInfoTest, SlotOfAnotherProvider_IsQueriedThroughItsOwner)
{
    auto hardware = MakeKeyManagement(ProviderType::kHardware);
    ASSERT_NE(hardware, nullptr);

    struct Case
    {
        const char* slot;
        IKeyManagementContext* owner;
        IKeyManagementContext* other;
    };
    std::uint16_t primary_providers[2]{};
    std::size_t index{0U};
    for (const auto& c :
         {Case{kOpenSslSlot, key_mgmt_.get(), hardware.get()}, Case{kPkcs11Slot, hardware.get(), key_mgmt_.get()}})
    {
        const auto slot = ResolveSlot(c.slot);
        auto from_owner = c.owner->GetKeySlotInfo(slot);
        auto from_other = c.other->GetKeySlotInfo(slot);
        ASSERT_TRUE(from_owner.has_value()) << c.slot;
        ASSERT_TRUE(from_other.has_value()) << c.slot;

        EXPECT_EQ(from_owner.value().state, KeySlotState::kOccupied) << c.slot;
        EXPECT_EQ(from_other.value().state, KeySlotState::kOccupied) << c.slot;
        EXPECT_EQ(from_other.value().primary_provider, from_owner.value().primary_provider) << c.slot;
        EXPECT_EQ(std::string_view{from_other.value().algorithm}, "HMAC-SHA256") << c.slot;
        primary_providers[index++] = from_owner.value().primary_provider;
    }
    EXPECT_NE(primary_providers[0], primary_providers[1]) << "The two slots must belong to different providers";
}

// Loading registers the key with the context's provider, so a slot owned by
// another provider is refused, as for binding a slot to a crypto context.
TEST_F(KeySlotInfoTest, LoadKey_SlotOfAnotherProvider_IsRefused)
{
    auto hardware = MakeKeyManagement(ProviderType::kHardware);
    ASSERT_NE(hardware, nullptr);

    struct Case
    {
        const char* slot;
        IKeyManagementContext* owner;
        IKeyManagementContext* other;
    };
    for (const auto& c :
         {Case{kOpenSslSlot, key_mgmt_.get(), hardware.get()}, Case{kPkcs11Slot, hardware.get(), key_mgmt_.get()}})
    {
        const auto slot = ResolveSlot(c.slot);
        auto refused = c.other->LoadKey(slot);
        ASSERT_FALSE(refused.has_value()) << c.slot;
        EXPECT_EQ(*refused.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kUnsupportedOperation))
            << c.slot << ": " << refused.error().Message();

        EXPECT_TRUE(c.owner->LoadKey(slot).has_value()) << c.slot;
    }
}
#endif  // SCORE_CRYPTO_HARDWARE_BACKEND_ENABLED

}  // namespace

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

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

#include "score/crypto/src/daemon/provider/handler/handler_init_params.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/sign_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/verify_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/score_provider/iav_primula/iav_primula_provider.hpp"
#include "score/crypto/src/daemon/provider/score_provider/iav_primula/key_management/iav_primula_key_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/iav_primula/operations/sign/iav_primula_sign_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/iav_primula/operations/verify/iav_primula_verify_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/factory/score_handler_factory.hpp"

#include <gtest/gtest.h>

namespace
{
using namespace score::crypto::daemon;
using namespace score::crypto::daemon::provider;
using namespace score::crypto::daemon::provider::score_provider;
using namespace score::crypto::daemon::provider::score_provider::iav_primula;

// ---------------------------------------------------------------------------
// SIGN handler creation and initialization
// ---------------------------------------------------------------------------

TEST(IavPrimulaApplicationIntegrationTest, CreatesSignHandlerFromProviderToAlgorithm)
{
    // Initialize the provider with the test provider ID and provider name.
    IavPrimulaProvider provider;
    ASSERT_TRUE(provider.Initialize(ProviderInitContext{common::ProviderId{7U}, "iavPrimula"}));

    // Create the provider-neutral factory and request an ML-DSA SIGN handler.
    auto factory = provider.GetCryptoHandlerFactory();
    ASSERT_NE(factory, nullptr);
    auto created = factory->CreateHandler("SIGN", "ML-DSA-44");
    ASSERT_TRUE(created.has_value());
    auto handler = created.value();
    ASSERT_NE(handler, nullptr);
    auto* primula_handler = dynamic_cast<IavPrimulaSignHandler*>(handler.get());
    ASSERT_NE(primula_handler, nullptr);
    EXPECT_EQ(primula_handler->GetAlgorithm(), "ML-DSA-44");

    // Use a non-null sentinel to simulate a bound native key handle without
    // creating a real backend key.
    IavPrimulaKeyHandler key{reinterpret_cast<iav_primula_key_handle*>(0x1), {}, {}};
    handler::InitializationParams params{};
    params.bound_key_handler = &key;
    ASSERT_TRUE(handler->InitializeContext(params).has_value());
    EXPECT_EQ(primula_handler->GetOperationState(), common::StreamOperationState::IDLE);

    // Initialization without a bound key must be rejected.
    auto missing_key_initialization = handler->InitializeContext({});
    ASSERT_FALSE(missing_key_initialization.has_value());
    EXPECT_EQ(missing_key_initialization.error(), common::DaemonErrorCode::kKeySlotEmpty);
    provider.Shutdown();
}

// ---------------------------------------------------------------------------
// VERIFY handler creation and initialization
// ---------------------------------------------------------------------------

TEST(IavPrimulaApplicationIntegrationTest, CreatesVerifyHandlerAndReachesAlgorithmValidation)
{
    // Initialize the provider before obtaining its handler factory.
    IavPrimulaProvider provider;
    ASSERT_TRUE(provider.Initialize(ProviderInitContext{common::ProviderId{7U}, "iavPrimula"}));

    // Create a VERIFY handler for the ML-DSA-44 algorithm.
    auto created = provider.GetCryptoHandlerFactory()->CreateHandler("VERIFY", "ML-DSA-44");
    ASSERT_TRUE(created.has_value());
    auto handler = created.value();
    ASSERT_NE(handler, nullptr);
    auto* primula_handler = dynamic_cast<IavPrimulaVerifyHandler*>(handler.get());
    ASSERT_NE(primula_handler, nullptr);
    EXPECT_EQ(primula_handler->GetAlgorithm(), "ML-DSA-44");

    // A non-null sentinel represents a bound native key handle for initialization.
    IavPrimulaKeyHandler key{reinterpret_cast<iav_primula_key_handle*>(0x1), {}, {}};
    handler::InitializationParams params{};
    params.bound_key_handler = &key;
    ASSERT_TRUE(handler->InitializeContext(params).has_value());
    EXPECT_EQ(primula_handler->GetOperationState(), common::StreamOperationState::IDLE);

    // Public-only key material has no native handle and is incompatible with
    // the native-key-based verification implementation.
    IavPrimulaKeyHandler public_only_key{nullptr, std::vector<std::uint8_t>(1312U), {}};
    params.bound_key_handler = &public_only_key;
    auto incompatible_key_initialization = handler->InitializeContext(params);
    ASSERT_FALSE(incompatible_key_initialization.has_value());
    EXPECT_EQ(incompatible_key_initialization.error(), common::DaemonErrorCode::kIncompatibleKeyType);
    provider.Shutdown();
}
}  // namespace

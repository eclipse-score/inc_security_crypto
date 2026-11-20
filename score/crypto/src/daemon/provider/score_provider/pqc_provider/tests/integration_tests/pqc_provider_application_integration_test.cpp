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

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/daemon/common/algorithm_catalog.hpp"
#include "score/crypto/src/daemon/provider/handler/handler_init_params.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/sign_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/verify_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/score_provider/pqc_provider/pqc_provider.hpp"
#include "score/crypto/src/daemon/provider/score_provider/pqc_provider/key_management/pqc_provider_key_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/pqc_provider/operations/sign/pqc_provider_sign_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/pqc_provider/operations/verify/pqc_provider_verify_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/factory/score_handler_factory.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/sign/sign_executor.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/verify/verify_executor.hpp"

#include <gtest/gtest.h>

#include <array>

namespace
{
using namespace score::crypto::daemon;
using namespace score::crypto::daemon::provider;
using namespace score::crypto::daemon::provider::score_provider;
using namespace score::crypto::daemon::provider::score_provider::pqc_provider;

TEST(PqcProviderApplicationIntegrationTest, CreatesOnlySupportedSignatureHandlers)
{
    PqcProvider provider;
    ASSERT_TRUE(provider.Initialize(ProviderInitContext{common::ProviderId{7U}, "iavPqcProvider"}));
    const auto factory = provider.GetCryptoHandlerFactory();
    ASSERT_NE(factory, nullptr);

    for (const auto& algorithm : ::score::crypto::kAlgorithmCatalog)
    {
        SCOPED_TRACE(algorithm.name);
        const bool supported = algorithm.id == ::score::crypto::Algorithm::kMlDsa44 ||
                               algorithm.id == ::score::crypto::Algorithm::kMlDsa65 ||
                               algorithm.id == ::score::crypto::Algorithm::kMlDsa87;
        EXPECT_EQ(PqcProviderSignHandler::IsAlgorithmSupported(algorithm), supported);
        EXPECT_EQ(PqcProviderVerifyHandler::IsAlgorithmSupported(algorithm), supported);

        for (const auto* handler_type : {"SIGN", "VERIFY"})
        {
            SCOPED_TRACE(handler_type);
            const auto created = factory->CreateHandler(handler_type, algorithm);
            if (supported)
            {
                ASSERT_TRUE(created.has_value());
                ASSERT_NE(created.value(), nullptr);
            }
            else
            {
                ASSERT_FALSE(created.has_value());
                EXPECT_EQ(*created.error(),
                          static_cast<::score::result::ErrorCode>(::score::crypto::CryptoErrorCode::kUnsupportedAlgorithm));
            }
        }
    }
    provider.Shutdown();
}

TEST(PqcProviderApplicationIntegrationTest, RejectsUnmappedAndIncompleteSignatureDescriptors)
{
    const auto supported = *::score::crypto::GetAlgorithmDescriptor("ML-DSA-44");
    auto unmapped = supported;
    unmapped.id = ::score::crypto::Algorithm::kUnknown;
    unmapped.name = "unmapped ML-DSA variant";
    auto missing_size = supported;
    missing_size.output_size = 0U;
    const std::array<::score::crypto::AlgorithmDescriptor, 2U> algorithms{{unmapped, missing_size}};

    PqcProvider provider;
    ASSERT_TRUE(provider.Initialize(ProviderInitContext{common::ProviderId{7U}, "iavPqcProvider"}));
    const auto factory = provider.GetCryptoHandlerFactory();
    ASSERT_NE(factory, nullptr);

    for (const auto& algorithm : algorithms)
    {
        SCOPED_TRACE(algorithm.name);
        EXPECT_FALSE(PqcProviderSignHandler::IsAlgorithmSupported(algorithm));
        EXPECT_FALSE(PqcProviderVerifyHandler::IsAlgorithmSupported(algorithm));
        for (const auto* handler_type : {"SIGN", "VERIFY"})
        {
            SCOPED_TRACE(handler_type);
            const auto created = factory->CreateHandler(handler_type, algorithm);
            ASSERT_FALSE(created.has_value());
            EXPECT_EQ(*created.error(),
                      static_cast<::score::result::ErrorCode>(::score::crypto::CryptoErrorCode::kUnsupportedAlgorithm));
        }

        PqcProviderSignHandler sign_handler{std::make_unique<operations::sign::SignExecutor>(), algorithm};
        PqcProviderVerifyHandler verify_handler{std::make_unique<operations::verify::VerifyExecutor>(), algorithm};
        EXPECT_EQ(sign_handler.GetSignatureSize(), 0U);
        EXPECT_EQ(verify_handler.GetSignatureSize(), 0U);
        const auto sign_initialized = sign_handler.InitializeContext({});
        const auto verify_initialized = verify_handler.InitializeContext({});
        ASSERT_FALSE(sign_initialized.has_value());
        ASSERT_FALSE(verify_initialized.has_value());
        EXPECT_EQ(sign_initialized.error(), common::DaemonErrorCode::kUnsupportedAlgorithm);
        EXPECT_EQ(verify_initialized.error(), common::DaemonErrorCode::kUnsupportedAlgorithm);
    }
    provider.Shutdown();
}

// ---------------------------------------------------------------------------
// SIGN handler creation and initialization
// ---------------------------------------------------------------------------

TEST(PqcProviderApplicationIntegrationTest, CreatesSignHandlerFromProviderToAlgorithm)
{
    // Initialize the provider with the test provider ID and provider name.
    PqcProvider provider;
    ASSERT_TRUE(provider.Initialize(ProviderInitContext{common::ProviderId{7U}, "iavPqcProvider"}));

    // Create the provider-neutral factory and request an ML-DSA SIGN handler.
    auto factory = provider.GetCryptoHandlerFactory();
    ASSERT_NE(factory, nullptr);
    auto created = factory->CreateHandler("SIGN", *::score::crypto::GetAlgorithmDescriptor("ML-DSA-44"));
    ASSERT_TRUE(created.has_value());
    auto handler = created.value();
    ASSERT_NE(handler, nullptr);
    auto* pqc_provider_handler = dynamic_cast<PqcProviderSignHandler*>(handler.get());
    ASSERT_NE(pqc_provider_handler, nullptr);
    EXPECT_EQ(pqc_provider_handler->GetAlgorithm().name, "ML-DSA-44");

    // Use a non-null sentinel to simulate a bound native key handle without
    // creating a real backend key.
    key_management::ProviderKeyHandle key_handle{};
    key_handle.provider_id = provider.GetProviderId();
    key_handle.algorithm = pqc_provider_handler->GetAlgorithm();
    key_handle.is_asymmetric = true;
    key_handle.material_kind = key_management::KeyMaterialKind::kPrivateKey;
    PqcProviderKeyHandler key{reinterpret_cast<pqc_provider_key_handle*>(0x1), {}, key_handle};
    handler::InitializationParams params{};
    params.provider_id = provider.GetProviderId();
    params.bound_key_handler = &key;
    ASSERT_TRUE(handler->InitializeContext(params).has_value());
    EXPECT_EQ(pqc_provider_handler->GetOperationState(), common::StreamOperationState::IDLE);

    // Initialization without a bound key must be rejected.
    auto missing_key_initialization = handler->InitializeContext({});
    ASSERT_FALSE(missing_key_initialization.has_value());
    EXPECT_EQ(missing_key_initialization.error(), common::DaemonErrorCode::kInvalidArgument);
    provider.Shutdown();
}

// ---------------------------------------------------------------------------
// VERIFY handler creation and initialization
// ---------------------------------------------------------------------------

TEST(PqcProviderApplicationIntegrationTest, CreatesVerifyHandlerAndReachesAlgorithmValidation)
{
    // Initialize the provider before obtaining its handler factory.
    PqcProvider provider;
    ASSERT_TRUE(provider.Initialize(ProviderInitContext{common::ProviderId{7U}, "iavPqcProvider"}));

    // Create a VERIFY handler for the ML-DSA-44 algorithm.
    auto created = provider.GetCryptoHandlerFactory()->CreateHandler("VERIFY", *::score::crypto::GetAlgorithmDescriptor("ML-DSA-44"));
    ASSERT_TRUE(created.has_value());
    auto handler = created.value();
    ASSERT_NE(handler, nullptr);
    auto* pqc_provider_handler = dynamic_cast<PqcProviderVerifyHandler*>(handler.get());
    ASSERT_NE(pqc_provider_handler, nullptr);
    EXPECT_EQ(pqc_provider_handler->GetAlgorithm().name, "ML-DSA-44");

    // A non-null sentinel represents a bound native key handle for initialization.
    key_management::ProviderKeyHandle key_handle{};
    key_handle.provider_id = provider.GetProviderId();
    key_handle.algorithm = pqc_provider_handler->GetAlgorithm();
    key_handle.is_asymmetric = true;
    key_handle.material_kind = key_management::KeyMaterialKind::kPrivateKey;
    PqcProviderKeyHandler key{reinterpret_cast<pqc_provider_key_handle*>(0x1), {}, key_handle};
    handler::InitializationParams params{};
    params.provider_id = provider.GetProviderId();
    params.bound_key_handler = &key;
    ASSERT_TRUE(handler->InitializeContext(params).has_value());
    EXPECT_EQ(pqc_provider_handler->GetOperationState(), common::StreamOperationState::IDLE);

    // Public-only key material has no native handle and is incompatible with
    // the native-key-based verification implementation.
    PqcProviderKeyHandler public_only_key{nullptr, std::vector<std::uint8_t>(1312U), key_handle};
    params.bound_key_handler = &public_only_key;
    auto incompatible_key_initialization = handler->InitializeContext(params);
    ASSERT_FALSE(incompatible_key_initialization.has_value());
    EXPECT_EQ(incompatible_key_initialization.error(), common::DaemonErrorCode::kIncompatibleKeyType);
    provider.Shutdown();
}
}  // namespace

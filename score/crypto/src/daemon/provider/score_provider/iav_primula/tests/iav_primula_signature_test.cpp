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
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/sign_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/score_provider/iav_primula/key_management/iav_primula_key_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/iav_primula/operations/sign/iav_primula_sign_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/sign/sign_executor.hpp"

#include <gtest/gtest.h>

#include <vector>

namespace
{
using namespace score::crypto::daemon;
using namespace score::crypto::daemon::provider::score_provider::iav_primula;
using Executor = score::crypto::daemon::provider::score_provider::operations::sign::SignExecutor;
constexpr common::ProviderId kProviderId{7U};

key_management::ProviderKeyHandle SignatureHandle(
    const char* algorithm = "ML-DSA-44",
    key_management::KeyMaterialKind material_kind = key_management::KeyMaterialKind::kPrivateKey)
{
    key_management::ProviderKeyHandle handle{};
    handle.provider_id = kProviderId;
    handle.algorithm = *::score::crypto::GetAlgorithmDescriptor(algorithm);
    handle.is_asymmetric = true;
    handle.material_kind = material_kind;
    return handle;
}

// ---------------------------------------------------------------------------
// Signature algorithm sizes
// ---------------------------------------------------------------------------

TEST(IavPrimulaSignatureTest, ReportsSupportedSizesAndRejectsKem)
{
    // Expected signature sizes for the supported ML-DSA variants.
    const std::pair<const char*, std::size_t> cases[] = {
        // ML-DSA-44: 2420 bytes, ML-DSA-65: 3309 bytes, ML-DSA-87: 4627 bytes.
        {"ML-DSA-44", 2420U},
        {"ML-DSA-65", 3309U},
        {"ML-DSA-87", 4627U}};
    for (const auto& test_case : cases)
    {
        IavPrimulaSignHandler handler{std::make_unique<Executor>(), *::score::crypto::GetAlgorithmDescriptor(test_case.first)};
        EXPECT_EQ(handler.GetSignatureSize(), test_case.second);
        common::RequestParameters request;
        auto result = handler.Execute(
            {common::actors::OP_ACTOR_SIGN_HANDLER,
             provider::handler::sign_handler_operations::SIGN_GET_SIZE}, request);
        ASSERT_TRUE(result.has_value());
        ASSERT_EQ(result->size(), 1U);
        EXPECT_EQ(std::get<std::uint64_t>(result->front()), test_case.second);
    }

    // A KEM algorithm is not a supported signature algorithm.
    IavPrimulaSignHandler unsupported_handler{std::make_unique<Executor>(), *::score::crypto::GetAlgorithmDescriptor("ML-KEM-768")};
    EXPECT_EQ(unsupported_handler.GetSignatureSize(), 0U);
    auto result = unsupported_handler.InitializeContext({});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kUnsupportedAlgorithm);
}

// ---------------------------------------------------------------------------
// Output buffer validation
// ---------------------------------------------------------------------------

TEST(IavPrimulaSignatureTest, ValidatesOutputBuffer)
{
    IavPrimulaSignHandler handler{std::make_unique<Executor>(), *::score::crypto::GetAlgorithmDescriptor("ML-DSA-44")};
    // Use a non-null sentinel to simulate a bound native key handle without
    // creating a real backend key.
    const auto key_handle = SignatureHandle();
    IavPrimulaKeyHandler key{reinterpret_cast<iav_primula_key_handle*>(0x1), {}, key_handle};
    ::score::crypto::daemon::provider::handler::InitializationParams params{};
    params.provider_id = kProviderId;
    params.bound_key_handler = &key;
    ASSERT_TRUE(handler.InitializeContext(params).has_value());

    const std::uint8_t message[] = {1U, 2U};
    // ML-DSA-44 signatures require 2420 bytes; ten bytes are intentionally too small.
    std::vector<std::uint8_t> output(10U);
    const auto input = score::cpp::span<const std::uint8_t>{message, 2U};
    auto result = handler.SingleShotSign(input, score::cpp::span<std::uint8_t>{output.data(), output.size()});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kInsufficientBufferSize);
}

TEST(IavPrimulaSignatureTest, ValidatesSingleShotRequestAndPropagatesBackendFailure)
{
    namespace ops = provider::handler::sign_handler_operations;
    IavPrimulaSignHandler handler{std::make_unique<Executor>(), *::score::crypto::GetAlgorithmDescriptor("ML-DSA-44")};
    // The current FFI is a placeholder and never dereferences this sentinel.
    const auto key_handle = SignatureHandle();
    IavPrimulaKeyHandler key{reinterpret_cast<iav_primula_key_handle*>(0x1), {}, key_handle};
    provider::handler::InitializationParams params{};
    params.provider_id = kProviderId;
    params.bound_key_handler = &key;
    ASSERT_TRUE(handler.InitializeContext(params).has_value());
    const std::uint8_t message[] = {1U, 2U};
    const auto input = score::cpp::span<const std::uint8_t>{message, 2U};
    common::RequestParameters request{input};
    const common::OperationIdentifier operation{common::actors::OP_ACTOR_SIGN_HANDLER, ops::SIGN_SS};
    auto missing = handler.Execute(operation, request);
    ASSERT_FALSE(missing.has_value());
    EXPECT_EQ(missing.error(), common::DaemonErrorCode::kInsufficientParameters);

    request.emplace_back(std::uint64_t{0U});
    auto wrong_type = handler.Execute(operation, request);
    ASSERT_FALSE(wrong_type.has_value());
    EXPECT_EQ(wrong_type.error(), common::DaemonErrorCode::kInvalidDataType);

    std::vector<std::uint8_t> output(handler.GetSignatureSize());
    request[1] = score::cpp::span<std::uint8_t>{output.data(), output.size()};
    auto backend = handler.Execute(operation, request);
    ASSERT_FALSE(backend.has_value());
    EXPECT_EQ(backend.error(), common::DaemonErrorCode::kAlgorithmExecutionFailed);
    EXPECT_EQ(handler.GetOperationState(), common::StreamOperationState::IDLE);

    auto wrong_actor = handler.Execute({common::actors::OP_ACTOR_VERIFY_HANDLER, ops::SIGN_SS}, request);
    ASSERT_FALSE(wrong_actor.has_value());
    EXPECT_EQ(wrong_actor.error(), common::DaemonErrorCode::kInvalidOperation);
}

TEST(IavPrimulaSignatureTest, RequiresMatchingSignatureAlgorithm)
{
    const char* signature_algorithms[] = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"};
    const char* key_algorithms[] = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"};
    for (const auto* algorithm : signature_algorithms)
    {
        const auto descriptor = *::score::crypto::GetAlgorithmDescriptor(algorithm);
        for (const auto* key_algorithm : key_algorithms)
        {
            SCOPED_TRACE(algorithm);
            SCOPED_TRACE(key_algorithm);
            IavPrimulaSignHandler handler{std::make_unique<Executor>(), descriptor};
            const auto handle = SignatureHandle(key_algorithm);
            IavPrimulaKeyHandler key{reinterpret_cast<iav_primula_key_handle*>(0x1), {}, handle};
            provider::handler::InitializationParams params{};
            params.provider_id = kProviderId;
            params.bound_key_handler = &key;

            const auto result = handler.InitializeContext(params);
            if (handle.algorithm.id == descriptor.id)
            {
                EXPECT_TRUE(result.has_value());
            }
            else
            {
                ASSERT_FALSE(result.has_value());
                EXPECT_EQ(result.error(), common::DaemonErrorCode::kIncompatibleKeyType);
            }
        }
    }
}

TEST(IavPrimulaSignatureTest, RejectsNonPrivateSignatureMaterial)
{
    using key_management::KeyMaterialKind;
    const KeyMaterialKind kinds[] = {KeyMaterialKind::kUnspecified,
                                     KeyMaterialKind::kPublicKey,
                                     KeyMaterialKind::kSymmetricKey,
                                     KeyMaterialKind::kSharedSecret};
    for (const auto kind : kinds)
    {
        SCOPED_TRACE(static_cast<int>(kind));
        IavPrimulaSignHandler handler{std::make_unique<Executor>(),
                                      *::score::crypto::GetAlgorithmDescriptor("ML-DSA-44")};
        IavPrimulaKeyHandler key{
            reinterpret_cast<iav_primula_key_handle*>(0x1), {}, SignatureHandle("ML-DSA-44", kind)};
        provider::handler::InitializationParams params{};
        params.provider_id = kProviderId;
        params.bound_key_handler = &key;

        const auto result = handler.InitializeContext(params);
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error(), common::DaemonErrorCode::kIncompatibleKeyType);
    }
}

TEST(IavPrimulaSignatureTest, RejectsMissingNativeHandleAndClearsKeyAfterFailedRebind)
{
    IavPrimulaSignHandler handler{std::make_unique<Executor>(), *::score::crypto::GetAlgorithmDescriptor("ML-DSA-44")};
    IavPrimulaKeyHandler key{reinterpret_cast<iav_primula_key_handle*>(0x1), {}, SignatureHandle()};
    provider::handler::InitializationParams params{};
    params.provider_id = kProviderId;
    params.bound_key_handler = &key;
    ASSERT_TRUE(handler.InitializeContext(params).has_value());

    IavPrimulaKeyHandler missing_native_key{nullptr, {}, SignatureHandle()};
    params.bound_key_handler = &missing_native_key;
    const auto result = handler.InitializeContext(params);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kIncompatibleKeyType);

    const auto sign = handler.SingleShotSign({}, {});
    ASSERT_FALSE(sign.has_value());
    EXPECT_EQ(sign.error(), common::DaemonErrorCode::kKeySlotEmpty);
}
}  // namespace

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
#include "score/crypto/src/daemon/provider/handler/operations/kem_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/score_provider/iav_primula/key_management/iav_primula_key_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/iav_primula/operations/kem/iav_primula_kem_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/kem/kem_executor.hpp"

#include <gtest/gtest.h>

#include <vector>

namespace
{
using namespace score::crypto::daemon;
using namespace score::crypto::daemon::provider::score_provider::iav_primula;
using Executor = score::crypto::daemon::provider::score_provider::operations::kem::KemExecutor;

// ---------------------------------------------------------------------------
// Algorithm and input validation
// ---------------------------------------------------------------------------

TEST(IavPrimulaKemTest, RejectsUnsupportedAlgorithm)
{
    IavPrimulaKemHandler handler{std::make_unique<Executor>(), "ML-KEM-999"};
    auto result = handler.GenerateKeyPair();
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kUnsupportedAlgorithm);
}

TEST(IavPrimulaKemTest, PropagatesBackendStatusForKeyGeneration)
{
    IavPrimulaKemHandler handler{std::make_unique<Executor>(), "ML-KEM-768"};
    auto result = handler.GenerateKeyPair();
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kOperationFailed);
}

TEST(IavPrimulaKemTest, RejectsInvalidEncapsulationInput)
{
    IavPrimulaKemHandler handler{std::make_unique<Executor>(), "ML-KEM-768"};
    const std::uint8_t public_key[] = {1U, 2U};
    auto result = handler.Encapsulate(score::cpp::span<const std::uint8_t>{public_key, sizeof(public_key)});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kInvalidArgument);
}

TEST(IavPrimulaKemTest, RequiresBoundKeyForDecapsulation)
{
    IavPrimulaKemHandler handler{std::make_unique<Executor>(), "ML-KEM-768"};
    const std::uint8_t ciphertext[] = {1U, 2U};
    auto result = handler.Decapsulate(score::cpp::span<const std::uint8_t>{ciphertext, sizeof(ciphertext)});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kInvalidArgument);
}

// ---------------------------------------------------------------------------
// Backend status propagation
// ---------------------------------------------------------------------------

TEST(IavPrimulaKemTest, PropagatesBackendStatusForValidEncapsulation)
{
    IavPrimulaKemHandler handler{std::make_unique<Executor>(), "ML-KEM-768"};
    // ML-KEM-768 public keys contain 1184 bytes.
    const std::vector<std::uint8_t> public_key(1184U, 0U);
    auto result = handler.Encapsulate(score::cpp::span<const std::uint8_t>{public_key.data(), public_key.size()});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kOperationFailed);
}

TEST(IavPrimulaKemTest, PropagatesBackendStatusForValidDecapsulation)
{
    IavPrimulaKemHandler handler{std::make_unique<Executor>(), "ML-KEM-768"};
    // Use a non-null sentinel to simulate a bound native key handle. The
    // backend operation is expected to fail before dereferencing this handle.
    IavPrimulaKeyHandler key{reinterpret_cast<iav_primula_key_handle*>(0x1), {}, {}};
    ::score::crypto::daemon::provider::handler::InitializationParams params{};
    params.bound_key_handler = &key;
    ASSERT_TRUE(handler.InitializeContext(params).has_value());
    // ML-KEM-768 ciphertexts contain 1088 bytes.
    const std::vector<std::uint8_t> ciphertext(1088U, 0U);
    auto result = handler.Decapsulate(score::cpp::span<const std::uint8_t>{ciphertext.data(), ciphertext.size()});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kOperationFailed);
}

// ---------------------------------------------------------------------------
// Handler dispatch and context management
// ---------------------------------------------------------------------------

TEST(IavPrimulaKemTest, DispatchesOperationsAndReset)
{
    // Verify that the handler dispatches both a KEM operation and RESET.
    using namespace score::crypto::daemon::provider::handler::kem_handler_operations;
    IavPrimulaKemHandler handler{std::make_unique<Executor>(), "ML-KEM-768"};
    common::OperationIdentifier keygen{0U, KEM_KEYGEN};
    common::RequestParameters no_parameters{};
    auto keygen_result = handler.Execute(keygen, no_parameters);
    ASSERT_FALSE(keygen_result.has_value());
    EXPECT_EQ(keygen_result.error(), common::DaemonErrorCode::kOperationFailed);
    common::OperationIdentifier reset{0U, KEM_RESET};
    auto reset_result = handler.Execute(reset, no_parameters);
    ASSERT_TRUE(reset_result.has_value());
    EXPECT_TRUE(reset_result->empty());
}

TEST(IavPrimulaKemTest, AllowsContextWithoutBoundKey)
{
    IavPrimulaKemHandler handler{std::make_unique<Executor>(), "ML-KEM-768"};
    ::score::crypto::daemon::provider::handler::InitializationParams params{};
    // Context initialization is allowed without a bound key; decapsulation
    // validates that a key is available when the operation is executed.
    EXPECT_TRUE(handler.InitializeContext(params).has_value());
}
}  // namespace

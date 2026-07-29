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

#include "score/crypto/src/daemon/provider/score_provider/operations/random/score_random_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/random/random_executor.hpp"

namespace score::crypto::daemon::provider::score_provider::operations::random
{

using common::DaemonErrorCode;
using common::ResponseParameters;

ScoreRandomHandler::ScoreRandomHandler(std::unique_ptr<RandomExecutor> executor, const common::AlgorithmId& algorithm)
    : m_algorithm{algorithm}, m_executor{std::move(executor)}
{
}

Expected<ResponseParameters, DaemonErrorCode> ScoreRandomHandler::Execute(
    const common::OperationIdentifier& operationId,
    common::RequestParameters& request)
{
    return m_executor->Execute(*this, operationId, request);
}

Expected<std::monostate, DaemonErrorCode> ScoreRandomHandler::InitializeContext(
    const handler::InitializationParams& /*init_params*/)
{
    // A random context holds no per-request state and binds no key, so there is
    // nothing to set up beyond what the constructor already did.
    return std::monostate{};
}

Expected<std::monostate, DaemonErrorCode> ScoreRandomHandler::Reset()
{
    return std::monostate{};
}

// ---------------------------------------------------------------------------
// Default typed operations — return unsupported unless overridden
// ---------------------------------------------------------------------------

Expected<std::size_t, DaemonErrorCode> ScoreRandomHandler::GenerateRandom(score::cpp::span<std::uint8_t> /*output*/)
{
    return make_unexpected(DaemonErrorCode::kUnsupportedOperation);
}

Expected<std::monostate, DaemonErrorCode> ScoreRandomHandler::SeedRandom(const common::RequestParameter& /*seed*/)
{
    return make_unexpected(DaemonErrorCode::kUnsupportedOperation);
}

}  // namespace score::crypto::daemon::provider::score_provider::operations::random

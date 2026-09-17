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

#include "score/crypto/src/daemon/provider/score_provider/operations/kem/score_kem_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/kem/kem_executor.hpp"

namespace score::crypto::daemon::provider::score_provider::operations::kem
{

ScoreKemHandler::ScoreKemHandler(std::unique_ptr<KemExecutor> executor, common::AlgorithmId algorithm)
    : m_algorithm{std::move(algorithm)}, m_executor{std::move(executor)}
{
}

ScoreKemHandler::~ScoreKemHandler() = default;

Expected<common::ResponseParameters, common::DaemonErrorCode> ScoreKemHandler::Execute(
    const common::OperationIdentifier& operation,
    common::RequestParameters& request)
{
    // Delegate operation dispatch to the injected KEM executor.
    return m_executor->Execute(*this, operation, request);
}

Expected<std::monostate, common::DaemonErrorCode> ScoreKemHandler::InitializeContext(
    const handler::InitializationParams&)
{
    // The provider-neutral base handler has no context-specific state to initialize.
    return {};
}

Expected<std::monostate, common::DaemonErrorCode> ScoreKemHandler::Reset()
{
    // The provider-neutral base handler has no state to reset.
    return {};
}

// ---------------------------------------------------------------------------
// Default typed operations — return unsupported unless overridden
// ---------------------------------------------------------------------------

Expected<common::ResponseParameters, common::DaemonErrorCode> ScoreKemHandler::GenerateKeyPair()
{
    return make_unexpected(common::DaemonErrorCode::kUnsupportedOperation);
}
Expected<common::ResponseParameters, common::DaemonErrorCode> ScoreKemHandler::Encapsulate(
    const common::RequestParameter&)
{
    return make_unexpected(common::DaemonErrorCode::kUnsupportedOperation);
}
Expected<common::ResponseParameters, common::DaemonErrorCode> ScoreKemHandler::Decapsulate(
    const common::RequestParameter&)
{
    return make_unexpected(common::DaemonErrorCode::kUnsupportedOperation);
}
}  // namespace score::crypto::daemon::provider::score_provider::operations::kem

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

#include "score/crypto/src/daemon/provider/score_provider/operations/verify/score_verify_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/verify/verify_executor.hpp"

namespace score::crypto::daemon::provider::score_provider::operations::verify
{

// The handler owns the executor and stores the algorithm used by the provider.
ScoreVerifyHandler::ScoreVerifyHandler(std::unique_ptr<VerifyExecutor> executor, const common::AlgorithmId algorithm)
    : m_algorithm{std::move(algorithm)}, m_executor{std::move(executor)}
{
}

ScoreVerifyHandler::~ScoreVerifyHandler() = default;

Expected<common::ResponseParameters, common::DaemonErrorCode> ScoreVerifyHandler::Execute(
    const common::OperationIdentifier& operation,
    common::RequestParameters& request)
{
    if (m_executor == nullptr)
    {
        // A missing executor indicates an invalid handler configuration.
        return make_unexpected(common::DaemonErrorCode::kInternalError);
    }

    // Delegate operation dispatch to the injected verification executor.
    return m_executor->Execute(*this, operation, request);
}

Expected<std::monostate, common::DaemonErrorCode> ScoreVerifyHandler::InitializeContext(
    const handler::InitializationParams& /*init_params*/)
{
    // Reset the streaming state when a new handler context is initialized.
    m_state = common::StreamOperationState::IDLE;
    return std::monostate{};
}

Expected<std::monostate, common::DaemonErrorCode> ScoreVerifyHandler::Reset()
{
    // Reset the streaming state; provider-specific resources are reset by
    // concrete handlers when they override this method.
    m_state = common::StreamOperationState::IDLE;
    return std::monostate{};
}

// ---------------------------------------------------------------------------
// Default typed operations — return unsupported unless overridden
// ---------------------------------------------------------------------------

Expected<std::monostate, common::DaemonErrorCode> ScoreVerifyHandler::InitVerify(
    std::optional<common::RequestParameter> /*initial_data*/)
{
    return make_unexpected(common::DaemonErrorCode::kUnsupportedOperation);
}

Expected<std::monostate, common::DaemonErrorCode> ScoreVerifyHandler::UpdateVerify(
    const common::RequestParameter& /*data*/)
{
    return make_unexpected(common::DaemonErrorCode::kUnsupportedOperation);
}

Expected<bool, common::DaemonErrorCode> ScoreVerifyHandler::FinalizeVerify(
    std::optional<common::RequestParameter> /*final_data*/,
    std::optional<common::RequestParameter> /*output*/)
{
    // The base implementation reports an unsupported operation rather than
    // false, which is reserved for an invalid signature after verification.
    return make_unexpected(common::DaemonErrorCode::kUnsupportedOperation);
}

Expected<bool, common::DaemonErrorCode> ScoreVerifyHandler::SingleShotVerify(
    const common::RequestParameter& /*data*/,
    const common::RequestParameter& /*signature*/)
{
    // The base implementation reports an unsupported operation rather than
    // false, which is reserved for an invalid signature after verification.
    return make_unexpected(common::DaemonErrorCode::kUnsupportedOperation);
}
}  // namespace score::crypto::daemon::provider::score_provider::operations::verify

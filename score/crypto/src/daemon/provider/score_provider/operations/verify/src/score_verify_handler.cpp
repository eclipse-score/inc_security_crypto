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
#include "score/crypto/src/daemon/common/algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/verify/verify_executor.hpp"

#include <string_view>
#include <utility>

namespace score::crypto::daemon::provider::score_provider::operations::verify
{

using common::DaemonErrorCode;
using common::ResponseParameters;
using common::StreamOperationState;

ScoreVerifyHandler::ScoreVerifyHandler(std::unique_ptr<VerifyExecutor> executor, const common::AlgorithmId& algorithm)
    : m_algorithm{algorithm}, m_state{StreamOperationState::IDLE}, m_executor{std::move(executor)}
{
}

ScoreVerifyHandler::~ScoreVerifyHandler() = default;

Expected<ResponseParameters, DaemonErrorCode> ScoreVerifyHandler::Execute(
    const common::OperationIdentifier& operationId,
    common::RequestParameters& request)
{
    return m_executor->Execute(*this, operationId, request);
}

Expected<std::monostate, DaemonErrorCode> ScoreVerifyHandler::InitializeContext(
    const handler::InitializationParams& /*init_params*/)
{
    m_state = StreamOperationState::IDLE;
    return std::monostate{};
}

Expected<std::monostate, DaemonErrorCode> ScoreVerifyHandler::Reset()
{
    m_state = StreamOperationState::IDLE;
    return std::monostate{};
}

// ---------------------------------------------------------------------------
// Default typed operations
// ---------------------------------------------------------------------------

std::size_t ScoreVerifyHandler::GetSignatureSize() const noexcept
{
    const auto curve = ::score::crypto::daemon::common::LookupEcCurveOfAlgorithm(
        std::string_view{m_algorithm.data(), m_algorithm.size()});
    return curve.has_value() ? curve->signature_size : 0U;
}

Expected<std::monostate, DaemonErrorCode> ScoreVerifyHandler::InitVerify()
{
    return make_unexpected(DaemonErrorCode::kUnsupportedOperation);
}

Expected<std::monostate, DaemonErrorCode> ScoreVerifyHandler::UpdateVerify(
    score::cpp::span<const std::uint8_t> /*data*/)
{
    return make_unexpected(DaemonErrorCode::kUnsupportedOperation);
}

Expected<bool, DaemonErrorCode> ScoreVerifyHandler::FinalizeVerify(score::cpp::span<const std::uint8_t> /*signature*/)
{
    return make_unexpected(DaemonErrorCode::kUnsupportedOperation);
}

Expected<bool, DaemonErrorCode> ScoreVerifyHandler::SingleShotVerify(score::cpp::span<const std::uint8_t> /*data*/,
                                                                     score::cpp::span<const std::uint8_t> /*signature*/)
{
    return make_unexpected(DaemonErrorCode::kUnsupportedOperation);
}

}  // namespace score::crypto::daemon::provider::score_provider::operations::verify

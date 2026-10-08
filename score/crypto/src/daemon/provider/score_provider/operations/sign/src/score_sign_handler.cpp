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

#include "score/crypto/src/daemon/provider/score_provider/operations/sign/score_sign_handler.hpp"
#include "score/crypto/src/daemon/common/algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/sign/sign_executor.hpp"

#include <string_view>
#include <utility>

namespace score::crypto::daemon::provider::score_provider::operations::sign
{

using common::DaemonErrorCode;
using common::ResponseParameters;
using common::StreamOperationState;

ScoreSignHandler::ScoreSignHandler(std::unique_ptr<SignExecutor> executor, const common::AlgorithmId& algorithm)
    : m_algorithm{algorithm}, m_state{StreamOperationState::IDLE}, m_executor{std::move(executor)}
{
}

ScoreSignHandler::~ScoreSignHandler() = default;

Expected<ResponseParameters, DaemonErrorCode> ScoreSignHandler::Execute(const common::OperationIdentifier& operationId,
                                                                        common::RequestParameters& request)
{
    return m_executor->Execute(*this, operationId, request);
}

Expected<std::monostate, DaemonErrorCode> ScoreSignHandler::InitializeContext(
    const handler::InitializationParams& /*init_params*/)
{
    m_state = StreamOperationState::IDLE;
    return std::monostate{};
}

Expected<std::monostate, DaemonErrorCode> ScoreSignHandler::Reset()
{
    m_state = StreamOperationState::IDLE;
    return std::monostate{};
}

// ---------------------------------------------------------------------------
// Default typed operations
// ---------------------------------------------------------------------------

std::size_t ScoreSignHandler::GetSignatureSize() const noexcept
{
    const auto curve = ::score::crypto::daemon::common::LookupEcCurveOfAlgorithm(
        std::string_view{m_algorithm.data(), m_algorithm.size()});
    return curve.has_value() ? curve->signature_size : 0U;
}

Expected<std::monostate, DaemonErrorCode> ScoreSignHandler::InitSign()
{
    return make_unexpected(DaemonErrorCode::kUnsupportedOperation);
}

Expected<std::monostate, DaemonErrorCode> ScoreSignHandler::UpdateSign(score::cpp::span<const std::uint8_t> /*data*/)
{
    return make_unexpected(DaemonErrorCode::kUnsupportedOperation);
}

Expected<std::size_t, DaemonErrorCode> ScoreSignHandler::FinalizeSign(score::cpp::span<std::uint8_t> /*signature*/)
{
    return make_unexpected(DaemonErrorCode::kUnsupportedOperation);
}

Expected<std::size_t, DaemonErrorCode> ScoreSignHandler::SingleShotSign(score::cpp::span<const std::uint8_t> /*data*/,
                                                                        score::cpp::span<std::uint8_t> /*signature*/)
{
    return make_unexpected(DaemonErrorCode::kUnsupportedOperation);
}

}  // namespace score::crypto::daemon::provider::score_provider::operations::sign

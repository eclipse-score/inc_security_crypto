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

#include "score/crypto/src/daemon/provider/score_provider/operations/signature/score_signature_handler.hpp"
#include "score/crypto/src/daemon/common/algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/signature/signature_executor.hpp"

#include <string_view>
#include <variant>

namespace score::crypto::daemon::provider::score_provider::operations::signature
{

using common::DaemonErrorCode;
using common::ResponseParameters;
using common::StreamOperationState;

namespace
{
/// CTX_CREATE wire slot carrying the OperationMode byte.
constexpr std::size_t kOperationModeParamIndex = 4U;
}  // namespace

ScoreSignatureHandler::ScoreSignatureHandler(std::unique_ptr<SignatureExecutor> executor,
                                             const common::AlgorithmId& algorithm)
    : m_algorithm{algorithm}, m_state{StreamOperationState::IDLE}, m_executor{std::move(executor)}
{
}

Expected<ResponseParameters, DaemonErrorCode> ScoreSignatureHandler::Execute(
    const common::OperationIdentifier& operationId,
    common::RequestParameters& request)
{
    return m_executor->Execute(*this, operationId, request);
}

void ScoreSignatureHandler::ExtractOperationMode(const handler::InitializationParams& init_params) noexcept
{
    if (init_params.context_creation_params.size() <= kOperationModeParamIndex)
    {
        return;
    }
    const auto* mode_val = std::get_if<std::uint8_t>(&init_params.context_creation_params[kOperationModeParamIndex]);
    if (mode_val != nullptr)
    {
        m_operation_mode = static_cast<score::crypto::OperationMode>(*mode_val);
    }
}

Expected<std::monostate, DaemonErrorCode> ScoreSignatureHandler::InitializeContext(
    const handler::InitializationParams& init_params)
{
    ExtractOperationMode(init_params);
    m_state = StreamOperationState::IDLE;
    return std::monostate{};
}

Expected<std::monostate, DaemonErrorCode> ScoreSignatureHandler::Reset()
{
    m_state = StreamOperationState::IDLE;
    return std::monostate{};
}

// ---------------------------------------------------------------------------
// Default typed operations
// ---------------------------------------------------------------------------

std::size_t ScoreSignatureHandler::GetSignatureSize() const noexcept
{
    const auto curve = ::score::crypto::daemon::common::LookupEcCurveOfAlgorithm(
        std::string_view{m_algorithm.data(), m_algorithm.size()});
    return curve.has_value() ? curve->signature_size : 0U;
}

Expected<std::monostate, DaemonErrorCode> ScoreSignatureHandler::InitSignature()
{
    return make_unexpected(DaemonErrorCode::kUnsupportedOperation);
}

Expected<std::monostate, DaemonErrorCode> ScoreSignatureHandler::UpdateSignature(
    const common::RequestParameter& /*data*/)
{
    return make_unexpected(DaemonErrorCode::kUnsupportedOperation);
}

Expected<std::size_t, DaemonErrorCode> ScoreSignatureHandler::FinalizeSign(score::cpp::span<std::uint8_t> /*signature*/)
{
    return make_unexpected(DaemonErrorCode::kUnsupportedOperation);
}

Expected<bool, DaemonErrorCode> ScoreSignatureHandler::FinalizeVerify(const common::RequestParameter& /*signature*/)
{
    return make_unexpected(DaemonErrorCode::kUnsupportedOperation);
}

}  // namespace score::crypto::daemon::provider::score_provider::operations::signature

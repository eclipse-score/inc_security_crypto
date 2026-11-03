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

#include "score/crypto/src/daemon/provider/score_provider/operations/hash/score_hash_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/hash/hash_executor.hpp"

namespace score::crypto::daemon::provider::score_provider::operations::hash
{

using common::DaemonErrorCode;
using common::ResponseParameters;
using common::StreamOperationState;

ScoreHashHandler::ScoreHashHandler(std::unique_ptr<HashExecutor> executor, const common::AlgorithmId& algorithm)
    : m_algorithm{algorithm}, m_state{StreamOperationState::IDLE}, m_executor{std::move(executor)}
{
}

Expected<ResponseParameters, DaemonErrorCode> ScoreHashHandler::Execute(const common::OperationIdentifier& operationId,
                                                                        common::RequestParameters& request)
{
    return m_executor->Execute(*this, operationId, request);
}

Expected<std::monostate, DaemonErrorCode> ScoreHashHandler::InitializeContext(
    const handler::InitializationParams& /*init_params*/)
{
    m_state = StreamOperationState::IDLE;
    return std::monostate{};
}

Expected<std::monostate, DaemonErrorCode> ScoreHashHandler::Reset()
{
    m_state = StreamOperationState::IDLE;
    return std::monostate{};
}

// ---------------------------------------------------------------------------
// Default typed operations — return unsupported unless overridden
// ---------------------------------------------------------------------------

Expected<std::monostate, DaemonErrorCode> ScoreHashHandler::InitHash()
{
    return make_unexpected(DaemonErrorCode::kUnsupportedOperation);
}

Expected<std::monostate, DaemonErrorCode> ScoreHashHandler::UpdateHash(
    const score::cpp::span<const std::uint8_t> /*dataToHash*/)
{
    return make_unexpected(DaemonErrorCode::kUnsupportedOperation);
}

Expected<ResponseParameters, DaemonErrorCode> ScoreHashHandler::FinalizeHash(
    const score::cpp::span<std::uint8_t> /*hashOutput*/)
{
    return make_unexpected(DaemonErrorCode::kUnsupportedOperation);
}

Expected<ResponseParameters, DaemonErrorCode> ScoreHashHandler::SingleShotHash(
    const score::cpp::span<const std::uint8_t> /*dataToHash*/,
    const score::cpp::span<std::uint8_t> /*outputHash*/)
{
    return make_unexpected(DaemonErrorCode::kUnsupportedOperation);
}

Expected<ResponseParameters, DaemonErrorCode> ScoreHashHandler::GetDigestSize() const
{
    const auto size = common::LookupDigestSize(std::string_view{m_algorithm.data(), m_algorithm.size()});
    if (!size.has_value())
    {
        return make_unexpected(DaemonErrorCode::kUnsupportedAlgorithm);
    }

    ResponseParameters response;
    response.push_back(static_cast<std::uint64_t>(size.value()));
    return response;
}

}  // namespace score::crypto::daemon::provider::score_provider::operations::hash

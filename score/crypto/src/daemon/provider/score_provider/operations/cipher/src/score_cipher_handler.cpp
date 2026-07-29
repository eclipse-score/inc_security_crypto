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

#include "score/crypto/src/daemon/provider/score_provider/operations/cipher/score_cipher_handler.hpp"
#include "score/crypto/src/daemon/common/algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/cipher/cipher_executor.hpp"

#include <string_view>
#include <variant>

namespace score::crypto::daemon::provider::score_provider::operations::cipher
{

using common::DaemonErrorCode;
using common::ResponseParameters;
using common::StreamOperationState;

namespace
{
/// CTX_CREATE wire slot carrying the cipher direction byte.
constexpr std::size_t kDirectionParamIndex = 4U;
}  // namespace

ScoreCipherHandler::ScoreCipherHandler(std::unique_ptr<CipherExecutor> executor, const common::AlgorithmId& algorithm)
    : m_algorithm{algorithm}, m_state{StreamOperationState::IDLE}, m_executor{std::move(executor)}
{
}

Expected<ResponseParameters, DaemonErrorCode> ScoreCipherHandler::Execute(
    const common::OperationIdentifier& operationId,
    common::RequestParameters& request)
{
    return m_executor->Execute(*this, operationId, request);
}

void ScoreCipherHandler::ExtractDirection(const handler::InitializationParams& init_params) noexcept
{
    if (init_params.context_creation_params.size() <= kDirectionParamIndex)
    {
        return;
    }
    const auto* direction_val = std::get_if<std::uint8_t>(&init_params.context_creation_params[kDirectionParamIndex]);
    if (direction_val != nullptr)
    {
        m_direction = static_cast<score::crypto::CipherDirection>(*direction_val);
    }
}

Expected<std::monostate, DaemonErrorCode> ScoreCipherHandler::InitializeContext(
    const handler::InitializationParams& init_params)
{
    ExtractDirection(init_params);
    m_state = StreamOperationState::IDLE;
    return std::monostate{};
}

Expected<std::monostate, DaemonErrorCode> ScoreCipherHandler::Reset()
{
    m_state = StreamOperationState::IDLE;
    return std::monostate{};
}

// ---------------------------------------------------------------------------
// Default typed operations — algorithm metadata is provider-independent, the
// actual crypto is not and returns unsupported unless overridden.
// ---------------------------------------------------------------------------

std::size_t ScoreCipherHandler::GetBlockSize() const noexcept
{
    const auto info =
        ::score::crypto::daemon::common::LookupCipher(std::string_view{m_algorithm.data(), m_algorithm.size()});
    return info.has_value() ? info->block_size : 0U;
}

std::size_t ScoreCipherHandler::GetIvSize() const noexcept
{
    const auto info =
        ::score::crypto::daemon::common::LookupCipher(std::string_view{m_algorithm.data(), m_algorithm.size()});
    return info.has_value() ? info->iv_size : 0U;
}

Expected<std::monostate, DaemonErrorCode> ScoreCipherHandler::InitCipher(std::optional<common::RequestParameter> /*iv*/)
{
    return make_unexpected(DaemonErrorCode::kUnsupportedOperation);
}

Expected<std::size_t, DaemonErrorCode> ScoreCipherHandler::UpdateCipher(const common::RequestParameter& /*input*/,
                                                                        score::cpp::span<std::uint8_t> /*output*/)
{
    return make_unexpected(DaemonErrorCode::kUnsupportedOperation);
}

Expected<std::size_t, DaemonErrorCode> ScoreCipherHandler::FinalizeCipher(score::cpp::span<std::uint8_t> /*output*/)
{
    return make_unexpected(DaemonErrorCode::kUnsupportedOperation);
}

}  // namespace score::crypto::daemon::provider::score_provider::operations::cipher

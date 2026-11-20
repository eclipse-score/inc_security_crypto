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

#include "score/crypto/src/daemon/provider/score_provider/pqc_provider/operations/sign/pqc_provider_sign_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/pqc_provider/pqc_provider_algorithm.hpp"
#include "score/crypto/src/daemon/provider/score_provider/pqc_provider/key_management/pqc_provider_key_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/sign/sign_executor.hpp"

#include "score/mw/log/logging.h"

#include <cstdint>
#include <utility>

namespace score::crypto::daemon::provider::score_provider::pqc_provider
{

using common::DaemonErrorCode;

PqcProviderSignHandler::PqcProviderSignHandler(std::unique_ptr<operations::sign::SignExecutor> executor,
                                             const AlgorithmDescriptor& algorithm)
    : ScoreSignHandler{std::move(executor), algorithm}
{
}

bool PqcProviderSignHandler::IsAlgorithmSupported(const AlgorithmDescriptor& algorithm) noexcept
{
    return IsSignatureSupported(algorithm);
}

Expected<std::monostate, DaemonErrorCode> PqcProviderSignHandler::ValidateAlgorithm() const
{
    if (!IsAlgorithmSupported(m_algorithm))
    {
        return make_unexpected(DaemonErrorCode::kUnsupportedAlgorithm);
    }
    return std::monostate{};
}

std::size_t PqcProviderSignHandler::GetSignatureSize() const noexcept
{
    return IsAlgorithmSupported(m_algorithm) ? m_algorithm.output_size : 0U;
}

Expected<std::monostate, DaemonErrorCode> PqcProviderSignHandler::InitializeContext(
    const ::score::crypto::daemon::provider::handler::InitializationParams& init_params)
{
    score::mw::log::LogDebug() << "DEBUG: PqcProviderSignHandler::InitializeContext called with algorithm:"
                               << m_algorithm.name;
    m_key = nullptr;

    // Validate the algorithm and bind the non-owning native key handle required
    // for signing.
    const auto algorithm_result = ValidateAlgorithm();
    if (!algorithm_result.has_value())
    {
        return make_unexpected(algorithm_result.error());
    }

    const auto base_result = ScoreSignHandler::InitializeContext(init_params);
    if (!base_result.has_value())
    {
        score::mw::log::LogError() << "ERROR: Base signature handler initialization failed in "
                                      "PqcProviderSignHandler::InitializeContext";
        return make_unexpected(base_result.error());
    }

    if (init_params.bound_key_handler == nullptr)
    {
        return make_unexpected(DaemonErrorCode::kInvalidArgument);
    }

    if (init_params.provider_id == common::kInvalidProviderId ||
        init_params.bound_key_handler->GetProviderId() != init_params.provider_id)
    {
        return make_unexpected(DaemonErrorCode::kInvalidArgument);
    }

    const auto& handle = init_params.bound_key_handler->GetHandle();
    if (handle.algorithm.id != m_algorithm.id || handle.material_kind != key_management::KeyMaterialKind::kPrivateKey)
    {
        return make_unexpected(DaemonErrorCode::kIncompatibleKeyType);
    }

    // The PqcProvider key factory creates PqcProviderKeyHandler instances for this provider.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast) -- provider identity checked above
    const auto* pqc_provider_key = static_cast<const PqcProviderKeyHandler*>(init_params.bound_key_handler);
    if (pqc_provider_key->GetNativeHandle() == nullptr)
    {
        return make_unexpected(DaemonErrorCode::kIncompatibleKeyType);
    }

    m_key = pqc_provider_key->GetNativeHandle();
    return std::monostate{};
}

Expected<std::size_t, DaemonErrorCode> PqcProviderSignHandler::SingleShotSign(
    score::cpp::span<const std::uint8_t> data,
    score::cpp::span<std::uint8_t> signature)
{
    const auto algorithm_result = ValidateAlgorithm();
    if (!algorithm_result.has_value())
    {
        return make_unexpected(algorithm_result.error());
    }

    if (m_key == nullptr)
    {
        return make_unexpected(DaemonErrorCode::kKeySlotEmpty);
    }

    const size_t expected_signature_length = GetSignatureSize();
    if (signature.data() == nullptr || signature.size() < expected_signature_length)
    {
        return make_unexpected(DaemonErrorCode::kInsufficientBufferSize);
    }

    std::size_t signature_length = expected_signature_length;
    const auto status = pqc_provider_sign(m_key, data.data(), data.size(), signature.data(), &signature_length);
    if (status != PqcProviderStatusOk || signature_length != expected_signature_length)
    {
        return make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    return signature_length;
}
}  // namespace score::crypto::daemon::provider::score_provider::pqc_provider

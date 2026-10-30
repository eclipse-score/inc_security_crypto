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

#include "score/crypto/src/daemon/provider/score_provider/iav_primula/operations/sign/iav_primula_sign_handler.hpp"
#include "score/crypto/src/daemon/common/algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/score_provider/iav_primula/key_management/iav_primula_key_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/sign/sign_executor.hpp"

#include "score/mw/log/logging.h"

#include <cstdint>
#include <utility>

namespace score::crypto::daemon::provider::score_provider::iav_primula
{

using common::DaemonErrorCode;

/// @brief Return the expected signature size for a PQC signature algorithm.
///
/// @return Signature size in bytes, or zero if the algorithm is not a
///         supported signature algorithm.
std::size_t SignatureSizeForAlgorithm(const common::AlgorithmId& algorithm)
{
    const auto info = common::LookupPqcAlgorithm(algorithm);
    if (info.has_value() && (info->kind == common::PqcAlgorithmKind::kSignature))
    {
        return info->signature_or_ciphertext_size;
    }
    return 0U;
}

IavPrimulaSignHandler::IavPrimulaSignHandler(std::unique_ptr<operations::sign::SignExecutor> executor,
                                             common::AlgorithmId algorithm)
    : ScoreSignHandler{std::move(executor), std::move(algorithm)}
{
}

Expected<std::monostate, DaemonErrorCode> IavPrimulaSignHandler::ValidateAlgorithm() const
{
    if (SignatureSizeForAlgorithm(m_algorithm) == 0U)
    {
        return make_unexpected(DaemonErrorCode::kUnsupportedAlgorithm);
    }
    return std::monostate{};
}

std::size_t IavPrimulaSignHandler::GetSignatureSize() const noexcept
{
    return SignatureSizeForAlgorithm(m_algorithm);
}

Expected<std::monostate, DaemonErrorCode> IavPrimulaSignHandler::InitializeContext(
    const ::score::crypto::daemon::provider::handler::InitializationParams& init_params)
{
    score::mw::log::LogDebug() << "DEBUG: IavPrimulaSignHandler::InitializeContext called with algorithm:"
                               << m_algorithm;

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
                                      "IavPrimulaSignHandler::InitializeContext";
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

    // The Primula key factory creates IavPrimulaKeyHandler instances for this provider.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast) -- provider identity checked above
    const auto* primula_key = static_cast<const IavPrimulaKeyHandler*>(init_params.bound_key_handler);
    if (primula_key->GetNativeHandle() == nullptr)
    {
        return make_unexpected(DaemonErrorCode::kIncompatibleKeyType);
    }

    m_key = primula_key->GetNativeHandle();
    return std::monostate{};
}

Expected<std::size_t, DaemonErrorCode> IavPrimulaSignHandler::SingleShotSign(
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
    const auto status = iav_sign(m_key, data.data(), data.size(), signature.data(), &signature_length);
    if (status != IavStatusOk || signature_length != expected_signature_length)
    {
        return make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    return signature_length;
}
}  // namespace score::crypto::daemon::provider::score_provider::iav_primula

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
#include <vector>

namespace score::crypto::daemon::provider::score_provider::iav_primula
{

using common::DaemonErrorCode;
using common::ResponseParameters;

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

std::size_t IavPrimulaSignHandler::GetExpectedSignatureSize() const noexcept
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
        return make_unexpected(DaemonErrorCode::kKeySlotEmpty);
    }

    const auto* primula_key = dynamic_cast<const IavPrimulaKeyHandler*>(init_params.bound_key_handler);
    if ((primula_key == nullptr) || (primula_key->GetNativeHandle() == nullptr))
    {
        return make_unexpected(DaemonErrorCode::kIncompatibleKeyType);
    }

    m_key = primula_key->GetNativeHandle();
    return std::monostate{};
}

Expected<std::monostate, DaemonErrorCode> IavPrimulaSignHandler::Reset()
{
    // Clear the internally owned signature buffer before resetting the base
    // handler state.
    m_outputBuffer.clear();
    return ScoreSignHandler::Reset();
}

Expected<ResponseParameters, DaemonErrorCode> IavPrimulaSignHandler::GetSignatureSize() const
{
    // Return the fixed signature size for the configured ML-DSA algorithm.
    const auto size = SignatureSizeForAlgorithm(m_algorithm);
    if (size == 0U)
    {
        return make_unexpected(DaemonErrorCode::kUnsupportedAlgorithm);
    }

    ResponseParameters response;
    response.emplace_back(static_cast<std::uint64_t>(size));
    return response;
}

Expected<ResponseParameters, DaemonErrorCode> IavPrimulaSignHandler::SingleShotSign(
    const common::RequestParameter& data,
    std::optional<common::RequestParameter> output)
{
    const auto algorithm_result = ValidateAlgorithm();
    if (!algorithm_result.has_value())
    {
        return make_unexpected(algorithm_result.error());
    }

    const auto* input = std::get_if<score::cpp::span<const std::uint8_t>>(&data);
    if (input == nullptr)
    {
        return make_unexpected(DaemonErrorCode::kInvalidDataType);
    }

    if (m_key == nullptr)
    {
        return make_unexpected(DaemonErrorCode::kKeySlotEmpty);
    }

    // Sign the input in a single operation. Use an internally owned buffer
    // when no output buffer is provided; otherwise write into the caller's buffer.
    const auto expected_signature_length = GetExpectedSignatureSize();
    std::uint8_t* signature_data = nullptr;
    const bool allocate_output_buffer = !output.has_value();

    if (!allocate_output_buffer)
    {
        auto* output_buffer = std::get_if<score::cpp::span<std::uint8_t>>(&output.value());
        if (output_buffer == nullptr)
        {
            return make_unexpected(DaemonErrorCode::kInvalidDataType);
        }
        if (output_buffer->data() == nullptr || output_buffer->size() < expected_signature_length)
        {
            return make_unexpected(DaemonErrorCode::kInsufficientBufferSize);
        }
        signature_data = output_buffer->data();
    }
    else
    {
        m_outputBuffer.clear();
        m_outputBuffer.resize(expected_signature_length);
        signature_data = m_outputBuffer.data();
    }

    std::size_t signature_length = expected_signature_length;
    const auto status = iav_sign(m_key, input->data(), input->size(), signature_data, &signature_length);
    if (status != IavStatusOk || signature_length != expected_signature_length)
    {
        return make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    // Return owned output for internally allocated storage and a non-owning
    // view for caller-provided storage.
    ResponseParameters response;
    if (allocate_output_buffer)
    {
        response.emplace_back(common::OwnedBuffer{std::move(m_outputBuffer)});
    }
    else
    {
        response.emplace_back(score::cpp::span<const std::uint8_t>{signature_data, signature_length});
    }
    return response;
}
}  // namespace score::crypto::daemon::provider::score_provider::iav_primula

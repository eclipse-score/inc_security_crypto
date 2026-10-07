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

#include "score/crypto/src/daemon/provider/score_provider/iav_primula/operations/verify/iav_primula_verify_handler.hpp"

#include "score/crypto/src/daemon/common/algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/score_provider/iav_primula/key_management/iav_primula_key_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/verify/verify_executor.hpp"

namespace score::crypto::daemon::provider::score_provider::iav_primula
{
namespace
{
/// @brief Return the expected signature size for a PQC signature algorithm.
///
/// @return Signature size in bytes, or zero if the algorithm is not a
///         supported signature algorithm.
std::size_t SignatureSize(const common::AlgorithmId& algorithm)
{
    const auto info = common::LookupPqcAlgorithm(algorithm);
    return info && info->kind == common::PqcAlgorithmKind::kSignature ? info->signature_or_ciphertext_size : 0U;
}
}  // namespace

IavPrimulaVerifyHandler::IavPrimulaVerifyHandler(std::unique_ptr<operations::verify::VerifyExecutor> executor,
                                                 common::AlgorithmId algorithm)
    : ScoreVerifyHandler{std::move(executor), std::move(algorithm)}
{
}

Expected<std::monostate, common::DaemonErrorCode> IavPrimulaVerifyHandler::ValidateAlgorithm() const
{
    if (SignatureSize(m_algorithm) == 0U)
    {
        return make_unexpected(common::DaemonErrorCode::kUnsupportedAlgorithm);
    }
    return std::monostate{};
}

Expected<std::monostate, common::DaemonErrorCode> IavPrimulaVerifyHandler::InitializeContext(
    const handler::InitializationParams& init_params)
{
    // Validate the algorithm and bind the non-owning native key handle required
    // for signature verification.
    auto algorithm = ValidateAlgorithm();
    if (!algorithm.has_value())
    {
        return make_unexpected(algorithm.error());
    }
    auto base = ScoreVerifyHandler::InitializeContext(init_params);
    if (!base.has_value())
    {
        return make_unexpected(base.error());
    }
    if (init_params.bound_key_handler == nullptr)
    {
        return make_unexpected(common::DaemonErrorCode::kKeySlotEmpty);
    }
    const auto* key = dynamic_cast<const IavPrimulaKeyHandler*>(init_params.bound_key_handler);
    if (key == nullptr || key->GetNativeHandle() == nullptr)
    {
        return make_unexpected(common::DaemonErrorCode::kIncompatibleKeyType);
    }
    m_key = key->GetNativeHandle();
    return std::monostate{};
}

Expected<bool, common::DaemonErrorCode> IavPrimulaVerifyHandler::SingleShotVerify(
    const common::RequestParameter& data,
    const common::RequestParameter& signature)
{
    // Verify a complete message and signature in a single operation.
    auto algorithm = ValidateAlgorithm();
    if (!algorithm.has_value())
    {
        return make_unexpected(algorithm.error());
    }
    const auto* message = std::get_if<score::cpp::span<const std::uint8_t>>(&data);
    const auto* sig = std::get_if<score::cpp::span<const std::uint8_t>>(&signature);
    if (message == nullptr || sig == nullptr)
    {
        return make_unexpected(common::DaemonErrorCode::kInvalidDataType);
    }
    if (m_key == nullptr)
    {
        return make_unexpected(common::DaemonErrorCode::kKeySlotEmpty);
    }
    if (sig->data() == nullptr || sig->size() != SignatureSize(m_algorithm))
    {
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }
    const auto status = iav_verify(m_key, message->data(), message->size(), sig->data(), sig->size());
    // Map backend verification status to the handler contract: an invalid
    // signature returns false, while backend errors are returned as failures.
    if (status == IavStatusVerificationFailed)
    {
        return false;
    }
    if (status != IavStatusOk)
    {
        return make_unexpected(common::DaemonErrorCode::kAlgorithmExecutionFailed);
    }
    return true;
}
}  // namespace score::crypto::daemon::provider::score_provider::iav_primula

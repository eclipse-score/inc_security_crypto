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
#include "score/crypto/src/daemon/provider/score_provider/iav_primula/iav_primula_algorithm.hpp"
#include "score/crypto/src/daemon/provider/score_provider/iav_primula/key_management/iav_primula_key_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/verify/verify_executor.hpp"

#include <utility>

namespace score::crypto::daemon::provider::score_provider::iav_primula
{
namespace
{
/// @brief Return the expected signature size for a PQC signature algorithm.
///
/// @return Signature size in bytes, or zero if the algorithm is not a
///         supported signature algorithm.
std::size_t SignatureSize(const AlgorithmDescriptor& algorithm)
{
    const auto info = common::LookupPqcAlgorithm(algorithm);
    return info && info->kind == common::PqcAlgorithmKind::kSignature ? info->signature_or_ciphertext_size : 0U;
}
}  // namespace

IavPrimulaVerifyHandler::IavPrimulaVerifyHandler(std::unique_ptr<operations::verify::VerifyExecutor> executor,
                                                 const AlgorithmDescriptor& algorithm)
    : ScoreVerifyHandler{std::move(executor), algorithm}
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
    m_key = nullptr;
    // Validate the algorithm and bind the non-owning key handler required
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
    const auto* bound_key = init_params.bound_key_handler;
    if (bound_key == nullptr || init_params.provider_id == common::kInvalidProviderId)
    {
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }
    if (bound_key->GetProviderId() != init_params.provider_id)
    {
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }
    const auto& handle = bound_key->GetHandle();
    if (handle.algorithm.id != m_algorithm.id || (handle.material_kind != key_management::KeyMaterialKind::kPublicKey &&
                                                  handle.material_kind != key_management::KeyMaterialKind::kPrivateKey))
    {
        return make_unexpected(common::DaemonErrorCode::kIncompatibleKeyType);
    }
    // The Primula key factory creates IavPrimulaKeyHandler instances for this provider.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast) -- provider identity checked above
    const auto* key = static_cast<const IavPrimulaKeyHandler*>(bound_key);
    if (key->GetNativeHandle() == nullptr)
    {
        // Imported public keys are stored as bytes without a native backend handle.
        std::size_t public_key_size{0U};
        if (handle.material_kind != key_management::KeyMaterialKind::kPublicKey ||
            key->GetPublicKey(public_key_size) == nullptr || public_key_size != m_algorithm.public_key_size)
        {
            return make_unexpected(common::DaemonErrorCode::kIncompatibleKeyType);
        }
    }
    m_key = key;
    return std::monostate{};
}

std::size_t IavPrimulaVerifyHandler::GetSignatureSize() const noexcept
{
    return SignatureSize(m_algorithm);
}

Expected<bool, common::DaemonErrorCode> IavPrimulaVerifyHandler::SingleShotVerify(
    score::cpp::span<const std::uint8_t> data,
    score::cpp::span<const std::uint8_t> signature)
{
    // Verify a complete message and signature in a single operation.
    auto algorithm = ValidateAlgorithm();
    if (!algorithm.has_value())
    {
        return make_unexpected(algorithm.error());
    }
    if (m_key == nullptr)
    {
        return make_unexpected(common::DaemonErrorCode::kKeySlotEmpty);
    }
    const auto* native_key = m_key->GetNativeHandle();
    std::size_t public_key_size{0U};
    const auto* public_key = m_key->GetPublicKey(public_key_size);
    // Release() clears both the native handle and the public-key bytes.
    if (native_key == nullptr && (public_key == nullptr || public_key_size != m_algorithm.public_key_size))
    {
        return make_unexpected(common::DaemonErrorCode::kKeySlotEmpty);
    }
    if (signature.data() == nullptr || signature.size() != GetSignatureSize())
    {
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }
    iav_status status;
    if (native_key != nullptr)
    {
        // Generated keys already have a native handle understood by the backend.
        status = iav_verify(native_key, data.data(), data.size(), signature.data(), signature.size());
    }
    else
    {
        // Imported public-key bytes belong to the handler bound through key management.
        // Pass their algorithm and size because there is no native handle to describe them.
        const auto signature_algorithm = Algorithm(m_algorithm);
        if (!signature_algorithm.has_value())
        {
            return make_unexpected(signature_algorithm.error());
        }
        status = iav_verify_public_key(signature_algorithm.value(),
                                       public_key,
                                       public_key_size,
                                       data.data(),
                                       data.size(),
                                       signature.data(),
                                       signature.size());
    }
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

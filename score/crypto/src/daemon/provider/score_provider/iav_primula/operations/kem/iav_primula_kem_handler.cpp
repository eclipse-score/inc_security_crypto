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

#include "score/crypto/src/daemon/provider/score_provider/iav_primula/operations/kem/iav_primula_kem_handler.hpp"

#include "score/crypto/src/daemon/common/algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/score_provider/iav_primula/key_management/iav_primula_key_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/kem/kem_executor.hpp"

#include <utility>
#include <vector>

namespace score::crypto::daemon::provider::score_provider::iav_primula
{

IavPrimulaKemHandler::IavPrimulaKemHandler(std::unique_ptr<operations::kem::KemExecutor> executor,
                                           common::AlgorithmId algorithm)
    : ScoreKemHandler(std::move(executor), std::move(algorithm))
{
}

Expected<iav_algorithm, common::DaemonErrorCode> IavPrimulaKemHandler::GetAlgorithm() const noexcept
{
    if (m_algorithm == "ML-KEM-512")
    {
        return IavAlgorithmMlKem512;
    }
    if (m_algorithm == "ML-KEM-768")
    {
        return IavAlgorithmMlKem768;
    }
    if (m_algorithm == "ML-KEM-1024")
    {
        return IavAlgorithmMlKem1024;
    }
    return make_unexpected(common::DaemonErrorCode::kUnsupportedAlgorithm);
}

Expected<std::monostate, common::DaemonErrorCode> IavPrimulaKemHandler::InitializeContext(
    const handler::InitializationParams& init_params)
{
    // Bind an optional IAV-Primula key. A key is required later for
    // decapsulation, but not for key generation or encapsulation.
    m_key = nullptr;
    if (init_params.bound_key_handler != nullptr)
    {
        const auto* key = dynamic_cast<const IavPrimulaKeyHandler*>(init_params.bound_key_handler);
        if (key == nullptr)
        {
            return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
        }
        m_key = key->GetNativeHandle();
    }
    return {};
}

Expected<common::ResponseParameters, common::DaemonErrorCode> IavPrimulaKemHandler::GenerateKeyPair()
{
    auto algorithm = GetAlgorithm();
    if (!algorithm.has_value())
    {
        return make_unexpected(algorithm.error());
    }

    // Generate a temporary KEM key pair, export its public key, and release the
    // native key handle before returning the public key.
    iav_primula_key_handle* key = nullptr;
    if (iav_kem_keypair_generate(algorithm.value(), &key) != IavStatusOk || key == nullptr)
    {
        return make_unexpected(common::DaemonErrorCode::kOperationFailed);
    }

    const auto info = common::LookupPqcAlgorithm(m_algorithm);
    std::vector<std::uint8_t> public_key(info->public_key_size);
    std::size_t length = public_key.size();
    const auto status = iav_kem_public_key_export(key, public_key.data(), &length);
    iav_key_destroy(key);
    if (status != IavStatusOk || length != public_key.size())
    {
        return make_unexpected(common::DaemonErrorCode::kOperationFailed);
    }
    return common::ResponseParameters{common::OwnedBuffer{std::move(public_key)}};
}

Expected<common::ResponseParameters, common::DaemonErrorCode> IavPrimulaKemHandler::Encapsulate(
    const common::RequestParameter& request)
{
    const auto* public_key = std::get_if<score::cpp::span<const std::uint8_t>>(&request);
    const auto info = common::LookupPqcAlgorithm(m_algorithm);
    auto algorithm = GetAlgorithm();
    if ((public_key == nullptr) || !info.has_value() || !algorithm.has_value() ||
        (public_key->size() != info->public_key_size))
    {
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }

    // Encapsulate a shared secret using the supplied public key. The response
    // contains the ciphertext followed by the shared secret.
    std::vector<std::uint8_t> ciphertext(info->signature_or_ciphertext_size);
    std::vector<std::uint8_t> secret(info->shared_secret_size);
    std::size_t ciphertext_length = ciphertext.size();
    std::size_t secret_length = secret.size();
    const auto status = iav_kem_encapsulate(algorithm.value(),
                                            public_key->data(),
                                            public_key->size(),
                                            ciphertext.data(),
                                            &ciphertext_length,
                                            secret.data(),
                                            &secret_length);
    if ((status != IavStatusOk) || (ciphertext_length != ciphertext.size()) || (secret_length != secret.size()))
    {
        return make_unexpected(common::DaemonErrorCode::kOperationFailed);
    }
    return common::ResponseParameters{common::OwnedBuffer{std::move(ciphertext)},
                                      common::OwnedBuffer{std::move(secret)}};
}

Expected<common::ResponseParameters, common::DaemonErrorCode> IavPrimulaKemHandler::Decapsulate(
    const common::RequestParameter& request)
{
    const auto* ciphertext = std::get_if<score::cpp::span<const std::uint8_t>>(&request);
    const auto info = common::LookupPqcAlgorithm(m_algorithm);
    if ((m_key == nullptr) || (ciphertext == nullptr) || !info.has_value() ||
        (ciphertext->size() != info->signature_or_ciphertext_size))
    {
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }

    // Decapsulate the ciphertext with the native key bound during context
    // initialization and return the resulting shared secret.
    std::vector<std::uint8_t> secret(info->shared_secret_size);
    std::size_t length = secret.size();
    const auto status = iav_kem_decapsulate(m_key, ciphertext->data(), ciphertext->size(), secret.data(), &length);
    if ((status != IavStatusOk) || (length != secret.size()))
    {
        return make_unexpected(common::DaemonErrorCode::kOperationFailed);
    }
    return common::ResponseParameters{common::OwnedBuffer{std::move(secret)}};
}

}  // namespace score::crypto::daemon::provider::score_provider::iav_primula

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

#include "score/crypto/src/daemon/provider/score_provider/iav_primula/key_management/iav_primula_key_factory.hpp"
#include "score/crypto/src/daemon/common/algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/score_provider/iav_primula/key_management/iav_primula_key_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/iav_primula/key_management/iav_primula_shared_secret_handler.hpp"
#include "score/iav_primula/include/iav_primula_ffi.h"

#include <memory>
#include <vector>

namespace score::crypto::daemon::provider::score_provider::iav_primula
{
namespace
{
/// @brief Map a PQC algorithm identifier to the IAV-Primula enum value.
///
/// @return The corresponding IAV-Primula algorithm, or
///         kUnsupportedAlgorithm if the identifier is unknown.
Expected<iav_algorithm, common::DaemonErrorCode> Algorithm(common::AlgorithmId algorithmId)
{
    auto algorithmDescription = std::string_view{algorithmId.data(), algorithmId.size()};
    if (algorithmDescription == "ML-DSA-44")
    {
        return IavAlgorithmMlDsa44;
    }
    if (algorithmDescription == "ML-DSA-65")
    {
        return IavAlgorithmMlDsa65;
    }
    if (algorithmDescription == "ML-DSA-87")
    {
        return IavAlgorithmMlDsa87;
    }
    if (algorithmDescription == "ML-KEM-512")
    {
        return IavAlgorithmMlKem512;
    }
    if (algorithmDescription == "ML-KEM-768")
    {
        return IavAlgorithmMlKem768;
    }
    if (algorithmDescription == "ML-KEM-1024")
    {
        return IavAlgorithmMlKem1024;
    }
    return make_unexpected(common::DaemonErrorCode::kUnsupportedAlgorithm);
}

Expected<const IavPrimulaKeyHandler*, common::DaemonErrorCode> ValidateKemKey(
    const key_management::IKeyHandler& handler,
    common::ProviderId provider_id,
    const common::AlgorithmId& algorithm,
    key_management::KeyMaterialKind kind)
{
    const auto* key = dynamic_cast<const IavPrimulaKeyHandler*>(&handler);
    if (key == nullptr || provider_id == common::kInvalidProviderId || handler.GetProviderId() != provider_id ||
        handler.GetHandle().provider_id != provider_id || handler.GetHandle().algorithm != algorithm ||
        handler.GetHandle().material_kind != kind)
    {
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }
    const auto& handle = handler.GetHandle();
    const auto granted_permissions =
        kind == key_management::KeyMaterialKind::kPublicKey
            ? handle.public_key_permissions.value_or(score::crypto::KeyOperationPermission::kAll)
            : handle.permissions;

    if (!score::crypto::HasPermission(granted_permissions, score::crypto::KeyOperationPermission::kAgree))
    {
        return make_unexpected(common::DaemonErrorCode::kKeyOperationNotPermitted);
    }
    return key;
}

Expected<std::size_t, common::DaemonErrorCode> GetKemCiphertextSize(
    common::ProviderId provider_id,
    const key_management::KeyEncapsulationRequest& request)
{
    const auto info = common::LookupPqcAlgorithm(request.algorithm);
    const auto algorithm = Algorithm(request.algorithm);
    if (!info || info->kind != common::PqcAlgorithmKind::kKem || !algorithm.has_value())
    {
        return make_unexpected(common::DaemonErrorCode::kUnsupportedAlgorithm);
    }
    auto key = ValidateKemKey(request.public_key, provider_id, request.algorithm, key_management::KeyMaterialKind::kPublicKey);
    if (!key.has_value())
    {
        return make_unexpected(key.error());
    }
    std::size_t size{0U};
    if (key.value()->GetPublicKey(size) == nullptr || size != info->public_key_size)
    {
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }
    return info->signature_or_ciphertext_size;
}
}  // namespace

Expected<key_management::IKeyHandler::Sptr, common::DaemonErrorCode> IavPrimulaKeyFactory::GenerateKey(
    const key_management::KeyGenerationRequest& r)
{
    auto info = common::LookupPqcAlgorithm(std::string_view{r.algorithm.data(), r.algorithm.size()});
    if (!info ||
        ((info->kind != common::PqcAlgorithmKind::kSignature) && (info->kind != common::PqcAlgorithmKind::kKem)))
    {
        return make_unexpected(common::DaemonErrorCode::kUnsupportedAlgorithm);
    }

    auto algorithm = Algorithm(r.algorithm);
    if (!algorithm.has_value())
    {
        return make_unexpected(algorithm.error());
    }

    iav_primula_key_handle* key = nullptr;
    const auto generate_status = (info->kind == common::PqcAlgorithmKind::kKem)
                                     ? iav_kem_keypair_generate(algorithm.value(), &key)
                                     : iav_keypair_generate(algorithm.value(), &key);
    if (generate_status != IavStatusOk || key == nullptr)
    {
        if (key != nullptr)
        {
            iav_key_destroy(key);
        }
        return make_unexpected(generate_status == IavStatusUnsupportedAlgorithm
                                   ? common::DaemonErrorCode::kUnsupportedAlgorithm
                                   : common::DaemonErrorCode::kOperationFailed);
    }

    // Keep the native key owned even if allocating the public-key cache fails.
    std::unique_ptr<iav_primula_key_handle, decltype(&iav_key_destroy)> native_key{key, &iav_key_destroy};
    std::vector<std::uint8_t> pub(info->public_key_size);
    std::size_t n = pub.size();
    const auto export_status = (info->kind == common::PqcAlgorithmKind::kKem)
                                   ? iav_kem_public_key_export(key, pub.data(), &n)
                                   : iav_public_key_export(key, pub.data(), &n);
    if (export_status != IavStatusOk || n != pub.size())
    {
        return make_unexpected(common::DaemonErrorCode::kOperationFailed);
    }

    key_management::ProviderKeyHandle h{};
    h.opaque_id = reinterpret_cast<std::uintptr_t>(key);
    h.provider_id = m_provider_id;
    h.permissions = r.permissions;
    h.public_key_permissions = r.public_key_permissions;
    h.is_asymmetric = true;
    h.algorithm = r.algorithm;
    h.key_size = info->private_key_size;
    h.material_kind = key_management::KeyMaterialKind::kPrivateKey;
    auto handler = std::make_shared<IavPrimulaKeyHandler>(key, std::move(pub), h);
    static_cast<void>(native_key.release());
    return handler;
}

Expected<key_management::IKeyHandler::Sptr, common::DaemonErrorCode> IavPrimulaKeyFactory::ImportKey(
    const key_management::KeyImportRequest& r)
{
    auto info = common::LookupPqcAlgorithm(std::string_view{r.algorithm.data(), r.algorithm.size()});
    if (r.format != score::crypto::FormatType::kRaw || !info ||
        ((info->kind != common::PqcAlgorithmKind::kSignature) && (info->kind != common::PqcAlgorithmKind::kKem)) ||
        !r.key_data || (r.key_data_size != info->public_key_size))
    {
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }

    std::vector<std::uint8_t> pub(r.key_data, r.key_data + r.key_data_size);
    key_management::ProviderKeyHandle h{};
    h.provider_id = m_provider_id;
    // Imports contain only public material. Preserve the import grant for
    // public operations and do not grant any private-key operations.
    h.permissions = score::crypto::KeyOperationPermission::kNone;
    h.public_key_permissions = r.permissions;
    h.is_asymmetric = true;
    h.algorithm = r.algorithm;
    h.key_size = info->public_key_size;
    h.material_kind = key_management::KeyMaterialKind::kPublicKey;
    return std::make_shared<IavPrimulaKeyHandler>(nullptr, std::move(pub), h);
}
Expected<std::size_t, common::DaemonErrorCode> IavPrimulaKeyFactory::GetEncapsulationCiphertextSize(
    const key_management::KeyEncapsulationRequest& request) const
{
    return GetKemCiphertextSize(m_provider_id, request);
}

Expected<key_management::ProviderEncapsulationResult, common::DaemonErrorCode> IavPrimulaKeyFactory::EncapsulateKey(
    const key_management::KeyEncapsulationRequest& request)
{
    auto ciphertext_size = GetKemCiphertextSize(m_provider_id, request);
    if (!ciphertext_size.has_value())
    {
        return make_unexpected(ciphertext_size.error());
    }

    const auto& key = static_cast<const IavPrimulaKeyHandler&>(request.public_key);
    std::size_t public_key_size{0U};
    const auto* public_key = key.GetPublicKey(public_key_size);
    const auto info = common::LookupPqcAlgorithm(request.algorithm);
    const auto algorithm = Algorithm(request.algorithm);
    std::vector<std::uint8_t> ciphertext(ciphertext_size.value());
    key_management::SecureKeyBytes secret(info->shared_secret_size);
    std::size_t ciphertext_length = ciphertext.size();
    std::size_t secret_length = secret.bytes.size();
    const auto status = iav_kem_encapsulate(algorithm.value(),
                                            public_key,
                                            public_key_size,
                                            ciphertext.data(),
                                            &ciphertext_length,
                                            secret.bytes.data(),
                                            &secret_length);
    if (status != IavStatusOk || ciphertext_length != ciphertext.size() || secret_length != secret.bytes.size())
    {
        return make_unexpected(status == IavStatusUnsupportedAlgorithm ? common::DaemonErrorCode::kUnsupportedAlgorithm
                                                                       : common::DaemonErrorCode::kOperationFailed);
    }
    return key_management::ProviderEncapsulationResult{
        std::move(ciphertext), std::make_shared<IavPrimulaSharedSecretHandler>(std::move(secret), m_provider_id)};
}

Expected<key_management::IKeyHandler::Sptr, common::DaemonErrorCode> IavPrimulaKeyFactory::DecapsulateKey(
    const key_management::KeyDecapsulationRequest& request)
{
    const auto info = common::LookupPqcAlgorithm(request.algorithm);
    const auto algorithm = Algorithm(request.algorithm);
    if (!info || info->kind != common::PqcAlgorithmKind::kKem || !algorithm.has_value())
    {
        return make_unexpected(common::DaemonErrorCode::kUnsupportedAlgorithm);
    }
    auto key = ValidateKemKey(request.private_key, m_provider_id, request.algorithm, key_management::KeyMaterialKind::kPrivateKey);
    if (!key.has_value())
    {
        return make_unexpected(key.error());
    }
    if (key.value()->GetNativeHandle() == nullptr || request.ciphertext.data() == nullptr ||
        request.ciphertext.size() != info->signature_or_ciphertext_size)
    {
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }

    key_management::SecureKeyBytes secret(info->shared_secret_size);
    std::size_t length = secret.bytes.size();
    const auto status = iav_kem_decapsulate(key.value()->GetNativeHandle(),
                                            request.ciphertext.data(),
                                            request.ciphertext.size(),
                                            secret.bytes.data(),
                                            &length);
    if (status != IavStatusOk || length != secret.bytes.size())
    {
        return make_unexpected(status == IavStatusUnsupportedAlgorithm ? common::DaemonErrorCode::kUnsupportedAlgorithm
                                                                       : common::DaemonErrorCode::kOperationFailed);
    }
    return std::make_shared<IavPrimulaSharedSecretHandler>(std::move(secret), m_provider_id);
}
}  // namespace score::crypto::daemon::provider::score_provider::iav_primula

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
#include "score/iav_primula/include/iav_primula_ffi.h"

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
        return make_unexpected(common::DaemonErrorCode::kOperationFailed);
    }

    std::vector<std::uint8_t> pub(info->public_key_size);
    std::size_t n = pub.size();
    const auto export_status = (info->kind == common::PqcAlgorithmKind::kKem)
                                   ? iav_kem_public_key_export(key, pub.data(), &n)
                                   : iav_public_key_export(key, pub.data(), &n);
    if (export_status != IavStatusOk || n != pub.size())
    {
        iav_key_destroy(key);
        return make_unexpected(common::DaemonErrorCode::kOperationFailed);
    }

    key_management::ProviderKeyHandle h{};
    h.opaque_id = reinterpret_cast<std::uintptr_t>(key);
    h.provider_id = m_provider_id;
    h.permissions = r.permissions;
    h.is_asymmetric = true;
    h.algorithm = r.algorithm;
    h.key_size = info->private_key_size;
    return std::make_shared<IavPrimulaKeyHandler>(key, std::move(pub), h);
}

Expected<key_management::IKeyHandler::Sptr, common::DaemonErrorCode> IavPrimulaKeyFactory::ImportKey(
    const key_management::KeyImportRequest& r)
{
    auto info = common::LookupPqcAlgorithm(std::string_view{r.algorithm.data(), r.algorithm.size()});
    if (!info ||
        ((info->kind != common::PqcAlgorithmKind::kSignature) && (info->kind != common::PqcAlgorithmKind::kKem)) ||
        !r.key_data || (r.key_data_size != info->public_key_size))
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);

    std::vector<std::uint8_t> pub(r.key_data, r.key_data + r.key_data_size);
    key_management::ProviderKeyHandle h{};
    h.provider_id = m_provider_id;
    h.permissions = r.permissions;
    h.is_asymmetric = true;
    h.algorithm = r.algorithm;
    h.key_size = info->public_key_size;
    return std::make_shared<IavPrimulaKeyHandler>(nullptr, std::move(pub), h);
}
}  // namespace score::crypto::daemon::provider::score_provider::iav_primula

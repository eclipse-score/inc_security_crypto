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

#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_rsa_key_pair.hpp"

#include "score/crypto/src/daemon/common/algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/detail/openssl_algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/detail/openssl_asymmetric_key.hpp"

#include <openssl/evp.h>  // EVP_PKEY_get_bits
#include <openssl/rsa.h>  // EVP_PKEY_CTX_set_rsa_keygen_bits

#include "score/mw/log/logging.h"

#include <cstddef>
#include <optional>
#include <string_view>

namespace score::crypto::daemon::provider::openssl
{

namespace
{
constexpr std::string_view kLogPrefix = "[OPENSSL_RSA_KEY_PAIR] ";

/// Modulus length in bytes of a claimed row, which is also the handle key_size of its key.
std::optional<std::size_t> LookupModulusSize(const ::score::crypto::AlgorithmDescriptor& algorithm) noexcept
{
    if (!IsRsaKeySupported(algorithm))
    {
        return std::nullopt;
    }
    return ::score::crypto::daemon::common::LookupKeySize(algorithm);
}
}  // namespace

bool IsRsaKeySupported(const ::score::crypto::AlgorithmDescriptor& algorithm) noexcept
{
    return (algorithm.key_type == ::score::crypto::KeyType::kRsa) &&
           (algorithm.category == ::score::crypto::AlgorithmCategory::kKey) &&
           detail::IsRsaModulusSupported(algorithm.key_bits);
}

::score::crypto::Expected<key_management::IKeyHandler::Sptr, ::score::crypto::daemon::common::DaemonErrorCode>
GenerateRsaKeyPair(common::ProviderId provider_id, const key_management::KeyGenerationRequest& request)
{
    const auto modulus_size = LookupModulusSize(request.algorithm);
    if (!modulus_size.has_value())
    {
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm);
    }

    const detail::KeygenSpec spec{"RSA", *modulus_size, "GenerateRsaKeyPair"};
    const std::size_t key_bits = request.algorithm.key_bits;
    return detail::GenerateAsymmetricKey(provider_id, request, spec, [bits = key_bits](EVP_PKEY_CTX* ctx) {
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, static_cast<int>(bits)) != 1)
        {
            score::mw::log::LogError() << kLogPrefix << "GenerateRsaKeyPair: failed to set key size to " << bits;
            return false;
        }
        return true;
    });
}

::score::crypto::Expected<key_management::IKeyHandler::Sptr, ::score::crypto::daemon::common::DaemonErrorCode>
ImportRsaKey(common::ProviderId provider_id, const key_management::KeyImportRequest& request)
{
    const auto modulus_size = LookupModulusSize(request.algorithm);
    if (!modulus_size.has_value())
    {
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm);
    }

    auto parsed = detail::ParseDerKey(request, EVP_PKEY_RSA);
    if (!parsed.has_value())
    {
        return ::score::crypto::make_unexpected(parsed.error());
    }

    if (EVP_PKEY_get_bits(parsed.value().pkey.get()) != static_cast<int>(request.algorithm.key_bits))
    {
        score::mw::log::LogError() << kLogPrefix << "ImportRsaKey: RSA modulus size is incompatible";
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kIncompatibleKeyType);
    }

    return detail::CreateImportedAsymmetricKey(provider_id, request, std::move(parsed.value()), *modulus_size);
}

}  // namespace score::crypto::daemon::provider::openssl

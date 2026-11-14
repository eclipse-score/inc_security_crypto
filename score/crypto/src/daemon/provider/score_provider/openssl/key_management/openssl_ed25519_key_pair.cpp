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

#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_ed25519_key_pair.hpp"

#include "score/crypto/src/daemon/common/algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/detail/openssl_asymmetric_key.hpp"

#include <openssl/evp.h>  // EVP_PKEY_ED25519

namespace score::crypto::daemon::provider::openssl
{

bool IsEd25519KeySupported(const ::score::crypto::AlgorithmDescriptor& algorithm) noexcept
{
    return algorithm.key_type == ::score::crypto::KeyType::kEd25519;
}

::score::crypto::Expected<key_management::IKeyHandler::Sptr, ::score::crypto::daemon::common::DaemonErrorCode>
GenerateEd25519KeyPair(common::ProviderId provider_id, const key_management::KeyGenerationRequest& request)
{
    const detail::KeygenSpec spec{
        "ED25519", ::score::crypto::daemon::common::kEd25519KeySize, "GenerateEd25519KeyPair"};
    return detail::GenerateAsymmetricKey(provider_id, request, spec);
}

::score::crypto::Expected<key_management::IKeyHandler::Sptr, ::score::crypto::daemon::common::DaemonErrorCode>
ImportEd25519Key(common::ProviderId provider_id, const key_management::KeyImportRequest& request)
{
    auto parsed = detail::ParseDerKey(request, EVP_PKEY_ED25519);
    if (!parsed.has_value())
    {
        return ::score::crypto::make_unexpected(parsed.error());
    }

    return detail::CreateImportedAsymmetricKey(
        provider_id, request, std::move(parsed.value()), ::score::crypto::daemon::common::kEd25519KeySize);
}

}  // namespace score::crypto::daemon::provider::openssl

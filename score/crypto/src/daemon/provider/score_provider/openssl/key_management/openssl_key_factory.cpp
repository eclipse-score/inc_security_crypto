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

#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_key_factory.hpp"

#include "score/crypto/src/daemon/common/algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_ec_key_pair.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_symmetric_key.hpp"

#include "score/mw/log/logging.h"

#include <string_view>

namespace score::crypto::daemon::provider::openssl
{

namespace
{
constexpr std::string_view kLogPrefix = "[OPENSSL_KEY_FACTORY] ";
}  // namespace

// Each key family claims the algorithms it serves; an identifier no family
// claims is unsupported. Further families (RSA, ML-DSA) add a branch.

OpenSslKeyFactory::OpenSslKeyFactory(common::ProviderId provider_id) : m_provider_id(provider_id){};

::score::crypto::Expected<key_management::IKeyHandler::Sptr, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslKeyFactory::GenerateKey(const key_management::KeyGenerationRequest& request)
{
    const std::string_view algorithm{request.algorithm.data(), request.algorithm.size()};
    if (::score::crypto::daemon::common::IsEcdsaAlgorithm(algorithm))
    {
        return GenerateEcKeyPair(m_provider_id, request);
    }
    if (IsSymmetricKeyAlgorithm(algorithm))
    {
        return GenerateSymmetricKey(m_provider_id, request);
    }

    score::mw::log::LogError() << kLogPrefix << "GenerateKey: unsupported algorithm '" << request.algorithm << "'";
    return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm);
}

::score::crypto::Expected<key_management::IKeyHandler::Sptr, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslKeyFactory::ImportKey(const key_management::KeyImportRequest& request)
{
    if ((request.key_data == nullptr) || (request.key_data_size == 0U))
    {
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    const std::string_view algorithm{request.algorithm.data(), request.algorithm.size()};
    if (::score::crypto::daemon::common::IsEcdsaAlgorithm(algorithm))
    {
        return ImportEcKey(m_provider_id, request);
    }
    if (IsSymmetricKeyAlgorithm(algorithm))
    {
        return ImportSymmetricKey(m_provider_id, request);
    }

    score::mw::log::LogError() << kLogPrefix << "ImportKey: unsupported algorithm '" << request.algorithm << "'";
    return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm);
}

}  // namespace score::crypto::daemon::provider::openssl

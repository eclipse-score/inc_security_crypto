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

#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/detail/openssl_asymmetric_key.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_ec_key_pair.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_ed25519_key_pair.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_rsa_key_pair.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_symmetric_key.hpp"

#include "score/mw/log/logging.h"

#include <string_view>

namespace score::crypto::daemon::provider::openssl
{

namespace
{
constexpr std::string_view kLogPrefix = "[OPENSSL_KEY_FACTORY] ";
}  // namespace

OpenSslKeyFactory::OpenSslKeyFactory(common::ProviderId provider_id) : m_provider_id(provider_id) {};

// Each key family claims the rows it serves; a row no family claims is unsupported.
// A further family adds one branch to each of GenerateKey and ImportKey.
::score::crypto::Expected<key_management::IKeyHandler::Sptr, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslKeyFactory::GenerateKey(const key_management::KeyGenerationRequest& request)
{
    if (IsEcKeySupported(request.algorithm))
    {
        return GenerateEcKeyPair(m_provider_id, request);
    }
    if (IsRsaKeySupported(request.algorithm))
    {
        return GenerateRsaKeyPair(m_provider_id, request);
    }
    if (IsEd25519KeySupported(request.algorithm))
    {
        return GenerateEd25519KeyPair(m_provider_id, request);
    }
    if (IsSymmetricKeySupported(request.algorithm))
    {
        return GenerateSymmetricKey(m_provider_id, request);
    }

    score::mw::log::LogError() << kLogPrefix << "GenerateKey: unsupported algorithm '" << request.algorithm.name << "'";
    return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm);
}

::score::crypto::Expected<key_management::IKeyHandler::Sptr, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslKeyFactory::ImportKey(const key_management::KeyImportRequest& request)
{
    if ((request.key_data == nullptr) || (request.key_data_size == 0U))
    {
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    if (IsEcKeySupported(request.algorithm))
    {
        return ImportEcKey(m_provider_id, request);
    }
    if (IsRsaKeySupported(request.algorithm))
    {
        return ImportRsaKey(m_provider_id, request);
    }
    if (IsEd25519KeySupported(request.algorithm))
    {
        return ImportEd25519Key(m_provider_id, request);
    }
    if (IsSymmetricKeySupported(request.algorithm))
    {
        const auto valid = ValidateSymmetricImport(request);
        if (!valid.has_value())
        {
            score::mw::log::LogError() << kLogPrefix << "ImportKey: " << request.key_data_size
                                       << " bytes are not a valid raw '" << request.algorithm.name << "' key";
            return ::score::crypto::make_unexpected(valid.error());
        }
        return ImportSymmetricKey(m_provider_id, request);
    }

    score::mw::log::LogError() << kLogPrefix << "ImportKey: unsupported algorithm '" << request.algorithm.name << "'";
    return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm);
}

::score::crypto::Expected<key_management::SecureKeyBytes, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslKeyFactory::ExportKey(const key_management::ProviderKeyHandle& handle,
                             std::optional<score::crypto::FormatType> format)
{
    // Secret and private key material never leaves the daemon in plaintext;
    // only the public half of a key pair is exported.
    if (!handle.is_asymmetric)
    {
        score::mw::log::LogError() << kLogPrefix << "ExportKey: secret keys are not exportable";
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kKeyNotExportable);
    }
    if (IsEcKeySupported(handle.algorithm))
    {
        return ExportEcPublicKey(handle, format);
    }
    if (IsRsaKeySupported(handle.algorithm) || IsEd25519KeySupported(handle.algorithm))
    {
        return detail::ExportSpkiPublicKey(handle, format);
    }

    score::mw::log::LogError() << kLogPrefix << "ExportKey: no export for algorithm '" << handle.algorithm.name << "'";
    return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
}

::score::crypto::Expected<std::size_t, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslKeyFactory::GetExportKeySize(const key_management::ProviderKeyHandle& handle,
                                    std::optional<score::crypto::FormatType> format)
{
    // Encode with the same code path ExportKey uses, so the advertised size can
    // never disagree with the exported bytes. The encoding is zeroised on return.
    const auto encoded = ExportKey(handle, format);
    if (!encoded.has_value())
    {
        return ::score::crypto::make_unexpected(encoded.error());
    }
    return encoded.value().bytes.size();
}

}  // namespace score::crypto::daemon::provider::openssl

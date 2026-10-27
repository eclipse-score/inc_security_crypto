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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_KEY_MANAGEMENT_OPENSSL_KEY_FACTORY_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_KEY_MANAGEMENT_OPENSSL_KEY_FACTORY_HPP

#include "score/crypto/src/daemon/key_management/interfaces/i_key_factory.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/i_key_handler.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_types.hpp"

namespace score::crypto::daemon::provider::openssl
{

/// OpenSSL implementation of IKeyFactory.
///
/// An algorithm naming an ECDSA curve yields an EC key pair, an AES or HMAC
/// algorithm a symmetric key, and any other algorithm kUnsupportedAlgorithm.
///
/// Each returned IKeyHandler (OpenSslKeyHandler) exclusively owns the material
/// of one key: a heap buffer zeroized with OPENSSL_cleanse, or an EVP_PKEY.
///
/// Thread safety: GenerateKey and ImportKey are safe to call concurrently
/// because each call allocates independent memory. The returned OpenSslKeyHandler
/// instances are not shared and require no additional locking.
class OpenSslKeyFactory final : public key_management::IKeyFactory
{
  public:
    OpenSslKeyFactory(common::ProviderId provider_id);
    ~OpenSslKeyFactory() override = default;

    OpenSslKeyFactory(const OpenSslKeyFactory&) = delete;
    OpenSslKeyFactory& operator=(const OpenSslKeyFactory&) = delete;
    OpenSslKeyFactory(OpenSslKeyFactory&&) = delete;
    OpenSslKeyFactory& operator=(OpenSslKeyFactory&&) = delete;

    /// Generate a key of the family named by request.algorithm.
    [[nodiscard]] ::score::crypto::Expected<key_management::IKeyHandler::Sptr,
                                            ::score::crypto::daemon::common::DaemonErrorCode>
    GenerateKey(const key_management::KeyGenerationRequest& request) override;

    /// Import raw symmetric key material, or a DER-encoded EC key.
    [[nodiscard]] ::score::crypto::Expected<key_management::IKeyHandler::Sptr,
                                            ::score::crypto::daemon::common::DaemonErrorCode>
    ImportKey(const key_management::KeyImportRequest& request) override;

  private:
    common::ProviderId m_provider_id{common::kInvalidProviderId};
};

}  // namespace score::crypto::daemon::provider::openssl

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_KEY_MANAGEMENT_OPENSSL_KEY_FACTORY_HPP

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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_OPENSSL_KEY_MANAGEMENT_OPENSSL_KEY_FACTORY_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_OPENSSL_KEY_MANAGEMENT_OPENSSL_KEY_FACTORY_HPP

#include "score/crypto/daemon/key_management/interfaces/i_key_factory.hpp"
#include "score/crypto/daemon/key_management/interfaces/i_key_handler.hpp"
#include "score/crypto/daemon/key_management/interfaces/key_types.hpp"

#include <cstddef>
#include <memory>
#include <string_view>

namespace score::crypto::daemon::provider::openssl
{

/// OpenSSL implementation of IKeyFactory.
///
/// Key material model:
///   GenerateKey — RAND_bytes → heap buffer → OpenSslKeyHandler (owns unique_ptr<uint8_t[]>)
///   ImportKey   — memcpy → heap buffer → OpenSslKeyHandler
///
/// Each returned IKeyHandler (OpenSslKeyHandler) owns exclusive heap memory for
/// one key. Zeroization uses OPENSSL_cleanse, which is guaranteed not to be
/// optimized away by the compiler.
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

    /// Generate a symmetric key using OpenSSL RAND_bytes.
    ///
    /// Key size is derived from request.algorithm:
    ///   HMAC-SHA256 → 32 B  |  HMAC-SHA384 → 48 B  |  HMAC-SHA512 → 64 B
    ///   AES-128-*   → 16 B  |  AES-192-*   → 24 B  |  AES-256-*   → 32 B
    [[nodiscard]] ::score::crypto::Expected<key_management::IKeyHandler::Sptr,
                                            ::score::crypto::daemon::common::DaemonErrorCode>
    GenerateKey(const key_management::KeyGenerationRequest& request) override;

    /// Import raw key material by copying into a new heap buffer.
    [[nodiscard]] ::score::crypto::Expected<key_management::IKeyHandler::Sptr,
                                            ::score::crypto::daemon::common::DaemonErrorCode>
    ImportKey(const key_management::KeyImportRequest& request) override;

  private:
    common::ProviderId m_provider_id{common::kInvalidProviderId};
    /// Map well-known algorithm names to symmetric key sizes in bytes.
    /// Returns 0 for unknown algorithms.
    [[nodiscard]] static std::size_t DetermineKeySize(const common::AlgorithmId& algorithm) noexcept;
};

}  // namespace score::crypto::daemon::provider::openssl

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_OPENSSL_KEY_MANAGEMENT_OPENSSL_KEY_FACTORY_HPP

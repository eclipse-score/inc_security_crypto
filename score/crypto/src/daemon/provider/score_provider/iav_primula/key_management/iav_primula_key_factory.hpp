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
/// @file iav_primula_key_factory.hpp
/// @brief Key factory for IAV-Primula provider keys.

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_IAV_PRIMULA_KEY_FACTORY_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_IAV_PRIMULA_KEY_FACTORY_HPP

#include "score/crypto/src/daemon/key_management/interfaces/i_key_factory.hpp"

namespace score::crypto::daemon::provider::score_provider::iav_primula
{

/// @brief IAV-Primula key factory for post-quantum algorithms.
///
/// Creates and imports key handlers for the supported ML-DSA and ML-KEM
/// parameter sets. Each generated key is associated with the provider ID
/// supplied during construction.
class IavPrimulaKeyFactory final : public key_management::IKeyFactory
{
  public:
    /// @brief Create a key factory for the specified provider instance.
    ///
    /// @param id Numeric identifier assigned to the provider.
    explicit IavPrimulaKeyFactory(common::ProviderId providerId) : m_provider_id(providerId) {}

    /// @brief Generate an IAV-Primula key pair.
    ///
    /// Supports the ML-DSA and ML-KEM parameter sets defined by the provider.
    /// The returned handler owns the native key handle and the exported public
    /// key material.
    [[nodiscard]] Expected<key_management::IKeyHandler::Sptr, common::DaemonErrorCode> GenerateKey(
        const key_management::KeyGenerationRequest&) override;

    /// @brief Import public key material for an IAV-Primula algorithm.
    ///
    /// Supports public keys for the ML-DSA and ML-KEM parameter sets defined by
    /// the provider. The key material is copied into the returned key handler.
    [[nodiscard]] Expected<key_management::IKeyHandler::Sptr, common::DaemonErrorCode> ImportKey(
        const key_management::KeyImportRequest&) override;

  private:
    common::ProviderId m_provider_id{};  ///< Numeric identifier of the owning provider instance.
};
}  // namespace score::crypto::daemon::provider::score_provider::iav_primula

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_IAV_PRIMULA_KEY_FACTORY_HPP

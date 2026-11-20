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
/// @file pqc_provider_key_factory.hpp
/// @brief Key factory for PQC Provider provider keys.

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_PQC_PROVIDER_KEY_FACTORY_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_PQC_PROVIDER_KEY_FACTORY_HPP

#include "score/crypto/src/daemon/key_management/interfaces/i_key_factory.hpp"

namespace score::crypto::daemon::provider::score_provider::pqc_provider
{

/// @brief PQC Provider key factory for post-quantum algorithms.
///
/// Creates and imports key handlers for the supported ML-DSA and ML-KEM
/// parameter sets. Each generated key is associated with the provider ID
/// supplied during construction.
class PqcProviderKeyFactory final : public key_management::IKeyFactory
{
  public:
    /// @brief Create a key factory for the specified provider instance.
    ///
    /// @param id Numeric identifier assigned to the provider.
    explicit PqcProviderKeyFactory(common::ProviderId providerId) : m_provider_id(providerId) {}

    /// @brief Generate an PQC Provider key pair.
    ///
    /// Supports the ML-DSA and ML-KEM parameter sets defined by the provider.
    /// The returned handler owns the native key handle and the exported public
    /// key material.
    [[nodiscard]] Expected<key_management::IKeyHandler::Sptr, common::DaemonErrorCode> GenerateKey(
        const key_management::KeyGenerationRequest&) override;

    /// @brief Import public key material for an PQC Provider algorithm.
    ///
    /// Supports public keys for the ML-DSA and ML-KEM parameter sets defined by
    /// the provider. The key material is copied into the returned key handler.
    /// Requires FormatType::kRaw and the exact algorithm-defined public-key size.
    [[nodiscard]] Expected<key_management::IKeyHandler::Sptr, common::DaemonErrorCode> ImportKey(
        const key_management::KeyImportRequest&) override;

    /// @brief Return the ciphertext size for an ML-KEM encapsulation request.
    ///
    /// Validates that the request contains an PQC Provider ML-KEM public key
    /// owned by this provider and permitted for key agreement. Does not create
    /// or register key material.
    [[nodiscard]] Expected<std::size_t, common::DaemonErrorCode> GetEncapsulationCiphertextSize(
        const key_management::KeyEncapsulationRequest&) const override;

    /// @brief Encapsulate to an PQC Provider ML-KEM public key.
    ///
    /// Returns the ciphertext and an owning, derive-only shared-secret handler.
    /// The caller registers the handler with KeyManagementService.
    [[nodiscard]] Expected<key_management::ProviderEncapsulationResult, common::DaemonErrorCode> EncapsulateKey(
        const key_management::KeyEncapsulationRequest&) override;

    /// @brief Decapsulate ML-KEM ciphertext with an PQC Provider private key.
    ///
    /// Returns an owning, derive-only shared-secret handler. The caller
    /// registers the handler with KeyManagementService.
    [[nodiscard]] Expected<key_management::IKeyHandler::Sptr, common::DaemonErrorCode> DecapsulateKey(
        const key_management::KeyDecapsulationRequest&) override;

  private:
    common::ProviderId m_provider_id{};  ///< Numeric identifier of the owning provider instance.
};
}  // namespace score::crypto::daemon::provider::score_provider::pqc_provider

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_PQC_PROVIDER_KEY_FACTORY_HPP

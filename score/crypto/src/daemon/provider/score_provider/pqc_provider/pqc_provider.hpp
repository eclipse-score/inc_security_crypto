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

/// @file pqc_provider.hpp
/// @brief PQC Provider provider implementation for the score interface.

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_PQC_PROVIDER_PROVIDER_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_PQC_PROVIDER_PROVIDER_HPP

#include <memory>

#include "score/crypto/src/daemon/provider/score_provider/score_provider.hpp"

namespace score::crypto::daemon::provider::score_provider::pqc_provider
{

/// @brief PQC Provider is a provider for post-quantum cryptographic algorithms.
///
/// Inherits ScoreProvider for provider lifecycle management and lazy handler
/// factory creation. Provides PQC Provider-specific key management and
/// cryptographic operation handlers without exposing implementation details
/// to the daemon core.
class PqcProvider final : public ::score::crypto::daemon::provider::score_provider::ScoreProvider
{
  public:
    PqcProvider() = default;
    ~PqcProvider() override = default;

    PqcProvider(const PqcProvider&) = delete;
    PqcProvider& operator=(const PqcProvider&) = delete;
    PqcProvider(PqcProvider&&) = delete;
    PqcProvider& operator=(PqcProvider&&) = delete;

    // --- IProvider lifecycle (PQC Provider-specific) ---
    void Shutdown() override;
    [[nodiscard]] bool InitialiseBackend(const ProviderInitContext& ctx) override;

    [[nodiscard]] common::ProviderCapability GetProviderCapabilities() override
    {
        return common::ProviderCapability::kCrypto | common::ProviderCapability::kKeyManagement;
    }

    // --- Key management capability ---
    std::shared_ptr<key_management::IKeyFactory> GetKeyFactory() override;
    std::shared_ptr<key_management::IKeySlotHandler> GetKeySlotHandler(
        const key_management::KeySlotConfig& config) override;
    void SetKeyManagementService(std::shared_ptr<key_management::KeyManagementService> service) override;

  protected:
    /// @brief Creates the PQC Provider-specific handler factory.
    [[nodiscard]] std::shared_ptr<handler::ICryptoHandlerFactory> CreateHandlerFactory() override;

  private:
    std::shared_ptr<key_management::IKeyFactory> m_factory;
    std::shared_ptr<key_management::KeyManagementService> m_keyManagementService;
};

}  // namespace score::crypto::daemon::provider::score_provider::pqc_provider

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_PQC_PROVIDER_PROVIDER_HPP

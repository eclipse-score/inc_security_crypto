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

/// @file iav_primula_provider.hpp
/// @brief IAV-Primula provider implementation for the score interface.

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_IAV_PRIMULA_PROVIDER_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_IAV_PRIMULA_PROVIDER_HPP

#include <memory>

#include "score/crypto/src/daemon/provider/score_provider/score_provider.hpp"

namespace score::crypto::daemon::provider::score_provider::iav_primula
{

/// @brief IAV-Primula is a provider for post-quantum cryptographic algorithms.
///
/// Inherits ScoreProvider for provider lifecycle management and lazy handler
/// factory creation. Provides IAV-Primula-specific key management and
/// cryptographic operation handlers without exposing implementation details
/// to the daemon core.
class IavPrimulaProvider final : public ::score::crypto::daemon::provider::score_provider::ScoreProvider
{
  public:
    IavPrimulaProvider() = default;
    ~IavPrimulaProvider() override = default;

    IavPrimulaProvider(const IavPrimulaProvider&) = delete;
    IavPrimulaProvider& operator=(const IavPrimulaProvider&) = delete;
    IavPrimulaProvider(IavPrimulaProvider&&) = delete;
    IavPrimulaProvider& operator=(IavPrimulaProvider&&) = delete;

    // --- IProvider lifecycle (IAV-Primula-specific) ---
    void Shutdown() override;
    [[nodiscard]] bool InitialiseBackend(const ProviderInitContext& ctx) override;

    // --- Key management capability ---
    std::shared_ptr<key_management::IKeyFactory> GetKeyFactory() override;
    std::shared_ptr<key_management::IKeySlotHandler> GetKeySlotHandler(
        const key_management::KeySlotConfig& config) override;
    void SetKeyManagementService(std::shared_ptr<key_management::KeyManagementService> service) override;

  protected:
    /// @brief Creates the IAV-Primula-specific handler factory.
    [[nodiscard]] std::shared_ptr<handler::ICryptoHandlerFactory> CreateHandlerFactory() override;

  private:
    std::shared_ptr<key_management::IKeyFactory> m_factory;
    std::shared_ptr<key_management::KeyManagementService> m_keyManagementService;
};

}  // namespace score::crypto::daemon::provider::score_provider::iav_primula

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_IAV_PRIMULA_PROVIDER_HPP

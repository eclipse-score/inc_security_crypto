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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_SCORE_PROVIDER_FACTORY_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_SCORE_PROVIDER_FACTORY_HPP

#include "score/crypto/daemon/provider/i_provider_factory.hpp"
#include "score/crypto/daemon/provider/score_provider/score_provider_config.hpp"

#include <vector>

namespace score::crypto::daemon::provider::score_provider
{

/// @brief Top-level factory for the score interface family.
///
/// Mirrors the Pkcs11ProviderFactory pattern: accepts a vector of configuration
/// entries, each describing a concrete score-interface provider to create.
/// CreateAndRegister() iterates the entries and delegates to the respective
/// internal provider factory (e.g. OpenSSLProviderFactory).
///
/// Configuration is supplied externally via SetConfigs() (the acceptor side of
/// the ScoreProviderConfig visitor pattern) or the explicit vector constructor.
/// The daemon bootstrapper delegates config setup to ScoreProviderConfig::Configure():
///
/// @code
///   config.GetScoreProviderConfig().PopulateDefaults();
///   auto factory = std::make_unique<ScoreProviderFactory>();
///   config.GetScoreProviderConfig().Configure(*factory);
///   provider_manager->RegisterFactory(std::move(factory));
/// @endcode
class ScoreProviderFactory final : public IProviderFactory
{
  public:
    /// Construct with default (empty) configuration.
    ScoreProviderFactory() = default;

    /// Construct with externally supplied provider configurations.
    explicit ScoreProviderFactory(std::vector<ScoreProviderEntry> configs);

    ~ScoreProviderFactory() override = default;

    /// @brief Accept a provider-config vector pushed by ScoreProviderConfig::Configure().
    ///
    /// This is the "acceptor" side of the visitor pattern: ScoreProviderConfig
    /// (the visitor) converts its ScoreProviderEntry list and hands them to
    /// the factory via this method.
    void SetConfigs(std::vector<ScoreProviderEntry> configs);

    /// Creates and registers all configured score providers.
    bool CreateAndRegister(ProviderManager& manager) override;

  private:
    std::vector<ScoreProviderEntry> m_configs;
};

}  // namespace score::crypto::daemon::provider::score_provider

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_SCORE_PROVIDER_FACTORY_HPP

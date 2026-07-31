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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_SCORE_PROVIDER_FACTORY_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_SCORE_PROVIDER_FACTORY_HPP

#include "score/crypto/src/daemon/provider/i_provider_factory.hpp"
#include "score/crypto/src/daemon/provider/score_provider/score_provider_config.hpp"

#include <vector>

namespace score::crypto::daemon::provider::score_provider
{

/// @brief Top-level factory for the score interface family.
///
/// Mirrors the Pkcs11ProviderFactory pattern: accepts a vector of configuration
/// entries, each describing a concrete score-interface provider to create.
/// CreateAndRegister() iterates the entries, constructs each IProvider via the
/// matching backend's ProviderCreator, and registers it into ProviderManager.
///
/// Configuration is supplied as one complete ScoreProviderFactoryConfig
/// snapshot. This prevents partially configured or order-dependent factories
/// when additional factory-wide options are added.
///
/// @code
///   ScoreProviderFactoryConfig factory_config{provider_entries};
///   auto factory = std::make_unique<ScoreProviderFactory>(std::move(factory_config));
///   provider_manager->RegisterFactory(std::move(factory));
/// @endcode
class ScoreProviderFactory final : public IProviderFactory
{
  public:
    explicit ScoreProviderFactory(ScoreProviderFactoryConfig config);

    ~ScoreProviderFactory() override = default;

    /// Creates and registers all configured score providers.
    bool CreateAndRegister(ProviderManager& manager) override;

  private:
    ScoreProviderFactoryConfig m_config;
};

}  // namespace score::crypto::daemon::provider::score_provider

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_SCORE_PROVIDER_FACTORY_HPP

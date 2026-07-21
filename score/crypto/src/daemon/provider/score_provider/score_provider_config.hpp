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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_CONFIG_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_CONFIG_HPP

#include <string>
#include <vector>

namespace score::crypto::daemon::provider::score_provider
{

// Forward declaration — Configure() is implemented in score_provider_config.cpp
// to keep this header free of factory internals.
class ScoreProviderFactory;

/// @brief Plain-data configuration entry for one score-interface provider.
///
/// All fields are standard-library types so this struct is usable by both the
/// generic daemon config reader (JSON / flatbuffer) and the bootstrapper
/// without pulling in any provider-internal headers.
struct ScoreProviderEntry
{
    /// Provider name used to register and look up this provider in ProviderManager.
    std::string providerName{};
    /// Implementation tag that selects the concrete factory, e.g. "openssl".
    std::string providerImpl{};
};

/// @brief Aggregates the ordered list of score-interface provider entries for the daemon.
///
/// This is the canonical score-provider configuration type.  The daemon's
/// top-level Config class holds one instance (via a type alias in the config
/// namespace) so that config.hpp does not need to define provider structures.
///
/// @par Visitor pattern
/// Configure() acts as a "visitor" that pushes the provider entries into a
/// ScoreProviderFactory.  The conversion from ScoreProviderEntry to internal
/// factory configuration lives entirely within the score_provider subsystem.
/// Typical bootstrapper usage:
/// @code
///   config.GetScoreProviderConfig().PopulateDefaults();
///   auto factory = std::make_unique<ScoreProviderFactory>();
///   config.GetScoreProviderConfig().Configure(*factory);
///   provider_manager->RegisterFactory(std::move(factory));
/// @endcode
class ScoreProviderConfig
{
  public:
    ScoreProviderConfig() = default;

    /// @brief Add a provider entry (called by parser or bootstrapper).
    void AddProviderEntry(ScoreProviderEntry entry)
    {
        m_providers.push_back(std::move(entry));
    }

    /// @brief Get all registered provider entries (read-only).
    const std::vector<ScoreProviderEntry>& GetProviderEntries() const
    {
        return m_providers;
    }

    /// @brief Populate production default provider entries when no config was loaded.
    ///
    /// Adds an OpenSSL software entry with standard defaults.  No-op if any
    /// provider entries are already present (e.g. loaded from file or test fixture).
    void PopulateDefaults();

    /// @brief Visit @p factory: convert each provider entry and configure the factory.
    ///
    /// Implemented out-of-line in score_provider_config.cpp so that this header
    /// remains free of factory internals.
    void Configure(ScoreProviderFactory& factory) const;

  private:
    std::vector<ScoreProviderEntry> m_providers;
};

}  // namespace score::crypto::daemon::provider::score_provider

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_CONFIG_HPP

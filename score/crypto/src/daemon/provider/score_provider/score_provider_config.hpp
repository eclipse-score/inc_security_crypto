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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_SCORE_PROVIDER_CONFIG_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_SCORE_PROVIDER_CONFIG_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"

#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace score::crypto::daemon::config
{
class Config;
}

namespace score::crypto::daemon::provider::score_provider
{

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
    /// Provider type (SOFTWARE, HARDWARE, etc.)
    /// Note: Uses string to avoid including common/types.hpp in config header
    std::string providerType{"SOFTWARE"};
};

/// @brief Complete configuration snapshot consumed by ScoreProviderFactory.
struct ScoreProviderFactoryConfig
{
    std::vector<ScoreProviderEntry> providers;
};

/// @brief Aggregates the ordered list of score-interface provider entries for the daemon.
///
/// This is the canonical score-provider configuration type.  The daemon's
/// top-level Config class holds one instance (via a type alias in the config
/// namespace) so that config.hpp does not need to define provider structures.
///
/// The provider manager bootstrapper parses this configuration and passes a
/// complete ScoreProviderFactoryConfig snapshot to the factory. Typical usage:
/// @code
///   config.GetScoreProviderConfig().ParseConfig(config);
///   ScoreProviderFactoryConfig factory_config{
///       config.GetScoreProviderConfig().GetConfig()};
///   auto factory = std::make_unique<ScoreProviderFactory>(std::move(factory_config));
///   auto result = factory->CreateAndRegister(*provider_manager);
/// @endcode
class ScoreProviderConfig
{
  public:
    ScoreProviderConfig() = default;

    /// @brief Add a provider entry (called by parser or bootstrapper).
    void AddProviderEntry(ScoreProviderEntry entry);

    /// @brief Get the complete factory configuration snapshot (read-only).
    const ScoreProviderFactoryConfig& GetConfig() const;

    /// @brief Parse configuration from backend implementations and populate provider entries.
    ///
    /// Unlike PKCS#11 (which selects one backend via label_flag), score providers support
    /// multiple simultaneous backends. This method aggregates provider entries from all
    /// enabled backends (OpenSSL, BoringSSL, etc.) that are linked into the build.
    /// Each backend contributes its ParseConfig() implementation. No-op if entries already present.
    /// @return Empty value on success, or a daemon error if parsing fails.
    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode> ParseConfig(config::Config& config);

  private:
    ScoreProviderFactoryConfig m_config;
};

}  // namespace score::crypto::daemon::provider::score_provider

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_SCORE_PROVIDER_CONFIG_HPP

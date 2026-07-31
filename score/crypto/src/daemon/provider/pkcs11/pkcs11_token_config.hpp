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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PKCS11_PKCS11_TOKEN_CONFIG_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PKCS11_PKCS11_TOKEN_CONFIG_HPP

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

namespace score::crypto::daemon::provider::pkcs11
{

/// @brief Plain-data configuration entry for one PKCS#11 token.
///
/// All fields are standard-library types so this struct is usable by both the
/// generic daemon config reader (JSON / flatbuffer) and the bootstrapper
/// without pulling in any PKCS#11 C headers.
struct Pkcs11TokenEntry
{
    /// Human-readable token label used for slot auto-discovery.
    std::string tokenLabel{};
    /// Optional model string for disambiguation when multiple tokens share the same label.
    std::string tokenModel{};
    /// User PIN for C_Login on first privileged session.  Empty = no login needed.
    std::string userPin{};
    /// Provider name used to register and look up this provider in ProviderManager.
    std::string providerName{};
    /// Provider Type used to register this provider in ProviderManager (HARDWARE or SOFTWARE).
    std::string providerType{"HARDWARE"};
    /// Cleanup strategy for session objects (soft vs hard cleanup).
    /// true = kHardCleanup (re-open session after every handler), false = kSoftCleanup.
    bool useHardCleanup{true};
};

/// @brief Complete configuration snapshot consumed by Pkcs11ProviderFactory.
struct Pkcs11ProviderFactoryConfig
{
    std::vector<Pkcs11TokenEntry> tokens;
};

/// @brief Aggregates the ordered list of PKCS#11 token entries for the daemon.
///
/// This is the canonical PKCS#11-specific configuration type. The daemon's
/// top-level Config class holds one instance (via a type alias in the config
/// namespace) so that config.hpp does not need to define PKCS#11 structures.
///
/// The provider manager bootstrapper parses this configuration and passes a
/// complete Pkcs11ProviderFactoryConfig snapshot to the factory. Typical usage:
/// @code
///   Pkcs11ProviderFactoryConfig factory_config{
///       config.GetPkcs11Config().GetConfig()};
///   auto factory = std::make_unique<Pkcs11ProviderFactory>(std::move(factory_config));
///   manager.RegisterFactory(std::move(factory));
/// @endcode
class Pkcs11Config
{
  public:
    Pkcs11Config() = default;

    /// @brief Add a token entry (called by parser or bootstrapper).
    void AddTokenEntry(Pkcs11TokenEntry entry)
    {
        m_config.tokens.push_back(std::move(entry));
    }

    /// @brief Get the complete factory configuration snapshot (read-only).
    const Pkcs11ProviderFactoryConfig& GetConfig() const
    {
        return m_config;
    }

    /// @brief Parse the configuration and populate the token information.
    ///
    /// This method parses the pkcs11 configuration and populates the token information.
    /// @return Empty value on success, or a daemon error if parsing fails.
    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode> ParseConfig(config::Config& config);

  private:
    Pkcs11ProviderFactoryConfig m_config;
};

}  // namespace score::crypto::daemon::provider::pkcs11

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PKCS11_PKCS11_TOKEN_CONFIG_HPP

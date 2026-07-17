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

#include <string>
#include <vector>

namespace score::crypto::daemon::provider::pkcs11
{

// Forward declaration — Configure() is implemented in pkcs11_token_config.cpp
// to keep this header free of PKCS#11 C API types (pkcs11_module.hpp).
class Pkcs11ProviderFactory;

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

/// @brief Aggregates the ordered list of PKCS#11 token entries for the daemon.
///
/// This is the canonical PKCS#11-specific configuration type. The daemon's
/// top-level Config class holds one instance (via a type alias in the config
/// namespace) so that config.hpp does not need to define PKCS#11 structures.
///
/// @par Visitor pattern
/// Configure() acts as a "visitor" that pushes the token entries into a
/// Pkcs11ProviderFactory. The conversion from Pkcs11TokenEntry to
/// Pkcs11ProviderConfig lives entirely within the PKCS#11 subsystem.
/// Typical bootstrapper usage:
/// @code
///   config.GetPkcs11Config().PopulateDefaults();
///   auto factory = std::make_unique<Pkcs11ProviderFactory>();
///   config.GetPkcs11Config().Configure(*factory);
///   manager.RegisterFactory(std::move(factory));
/// @endcode
class Pkcs11Config
{
  public:
    Pkcs11Config() = default;

    /// @brief Add a token entry (called by parser or bootstrapper).
    void AddTokenEntry(Pkcs11TokenEntry entry)
    {
        m_tokens.push_back(std::move(entry));
    }

    /// @brief Get all registered token entries (read-only).
    const std::vector<Pkcs11TokenEntry>& GetTokenEntries() const
    {
        return m_tokens;
    }

    /// @brief Parse the configuration and populate the token information.
    ///
    /// This method parses the pkcs11 configuration and populates the token information.
    void ParseConfig();

    /// @brief Visit @p factory: convert each token entry and configure the factory.
    ///
    /// Converts each Pkcs11TokenEntry to a Pkcs11ProviderConfig and calls
    /// factory.SetTokenConfigs().  Implemented out-of-line in
    /// pkcs11_token_config.cpp so that this header remains free of
    /// PKCS#11 C API types.
    void Configure(Pkcs11ProviderFactory& factory) const;

  private:
    std::vector<Pkcs11TokenEntry> m_tokens;
};

}  // namespace score::crypto::daemon::provider::pkcs11

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PKCS11_PKCS11_TOKEN_CONFIG_HPP

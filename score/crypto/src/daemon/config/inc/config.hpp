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

#ifndef SCORE_CRYPTO_DAEMON_CONFIG_CONFIG_HPP
#define SCORE_CRYPTO_DAEMON_CONFIG_CONFIG_HPP

#include "score/crypto/daemon/common/types.hpp"
#include "score/crypto/daemon/provider/pkcs11/pkcs11_token_config.hpp"
#include "score/crypto/daemon/provider/score_provider/score_provider_config.hpp"

#include <array>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

// TODO: Need to move the individual configs into their respective components (dependency inversion)
// The config component shall be demanded to fulfill the needs of the components not vice versa.

namespace score::crypto::daemon::config
{

// Configuration environment variable and default paths
/// @brief Environment variable name for specifying the configuration file path
constexpr std::string_view CRYPTO_CONFIG_FILE_ENV = "CRYPTO_CONFIG_FILE";

/// @brief Default configuration file paths (in order of preference)
const std::array<std::string_view, 1> DEFAULT_CONFIG_PATHS = {
    "./etc/crypto_config.bin",
};

// TODO: each component should define its own small config header (dependency inversion).
//  The config component is obligated to implement all relevant component configurations and e.g. load them from a
//  flatbuffer file.
//
//  How the config is passed into a constructor is handled via the respective factory methods. Only a factory will
//  decide which configuration load strategy will be used and how to acquire the component relevant configuration for
//  construction.
//  TODO: To use the function later. Only a place holder now. Rationale is to protect against resource exchaustion by
//  any application
/// @brief Resource quota policy — daemon-wide or provider-scoped limits on key creation per connection.
///
/// Owned by daemon configuration, not by individual key slots.
struct ResourceQuotaPolicy
{
    uint32_t max_ephemeral_keys_per_connection{32U};            ///< Per-connection ephemeral key limit
    uint32_t max_loaded_keys_per_connection{16U};               ///< Per-connection loaded-from-slot key limit
    uint64_t max_total_key_material_bytes{4U * 1024U * 1024U};  ///< Global 4 MiB cap
};

/**
 * @brief IPC/Communication configuration section
 */
class IPCConfig
{
  public:
    IPCConfig() = default;

    uint32_t GetNumOfIPCThreads() const
    {
        return m_num_ipc_threads;
    }
    const std::string& GetServerAddress() const
    {
        return m_server_address;
    }
    uint16_t GetServerPort() const
    {
        return m_server_port;
    }

    void SetNumOfIPCThreads(uint32_t threads)
    {
        m_num_ipc_threads = threads;
    }
    void SetServerAddress(const std::string& address)
    {
        m_server_address = address;
    }
    void SetServerPort(uint16_t port)
    {
        m_server_port = port;
    }

  private:
    uint32_t m_num_ipc_threads = 4;
    std::string m_server_address = "0.0.0.0";
    uint16_t m_server_port = 50051;
};

/**
 * @brief Provider configuration - contains metadata for adding a new provider
 *
 * This structure holds the necessary information to create and initialize a
 * provider. Providers are identified by their ProviderId and can be categorized
 * by CryptoProviderType. The actual provider instance creation is handled by
 * the factory implementation, which can be easily extended to support new
 * provider types.
 */
struct ProviderConfig
{
    common::ProviderId providerId;          ///< Unique provider identifier
    common::CryptoProviderType cryptoType;  ///< Functional category
    bool enabled;                           ///< Whether this provider should be initialized
    ResourceQuotaPolicy quota_policy{};     ///< Per-provider quota policy override

    ProviderConfig() = default;
    ProviderConfig(const common::ProviderId& id, common::CryptoProviderType cryptoType, bool enabled = true)
        : providerId(id), cryptoType(cryptoType), enabled(enabled)
    {
    }
};

/**
 * @brief Provider initialization configuration
 *
 * This structure defines the complete provider setup for the factory,
 * allowing daemon to configure which providers to initialize and set defaults
 * before calling Initialize().
 */
struct ProviderInitConfig
{
    std::vector<ProviderConfig> providers;  ///< List of providers to initialize
    std::unordered_map<common::CryptoProviderType, common::ProviderId>
        typeToProviderId;  ///< Mapping of provider types to their default
                           ///< ProviderId

    ProviderInitConfig() = default;

    /**
     * @brief Add a provider configuration
     * @param config Provider configuration to add
     */
    void AddProviderConfig(const ProviderConfig& config)
    {
        providers.push_back(config);
    }

    /**
     * @brief Set the default provider for a specific crypto provider type
     * @param cryptoType The functional category
     * @param providerId The provider ID to use for this type
     */
    void SetDefaultProviderForType(common::CryptoProviderType cryptoType, const common::ProviderId& providerId)
    {
        typeToProviderId[cryptoType] = providerId;
    }
};

/**
 * @brief General daemon configuration section
 */
class GeneralConfig
{
  public:
    GeneralConfig() = default;

    const std::string& GetLogLevel() const
    {
        return m_log_level;
    }
    uint32_t GetMaxSessions() const
    {
        return m_max_sessions;
    }
    const ResourceQuotaPolicy& GetQuotaPolicy() const
    {
        return m_quota_policy;
    }

    void SetLogLevel(const std::string& level)
    {
        m_log_level = level;
    }
    void SetMaxSessions(uint32_t max)
    {
        m_max_sessions = max;
    }
    void SetQuotaPolicy(const ResourceQuotaPolicy& quota_policy)
    {
        m_quota_policy = quota_policy;
    }

  private:
    std::string m_log_level = "info";
    uint32_t m_max_sessions = 100;
    ResourceQuotaPolicy m_quota_policy{};
};

/**
 * @brief Key management configuration section
 *
 * Stores key slot definitions parsed from the daemon's configuration source
 * (JSON manifest or flatbuffer). Each entry describes a persistent key slot:
 * its human-readable name, algorithm, owning provider, access policy, and
 * a deployment path that points to the external deployment descriptor.
 *
 * At daemon startup, a ConfigDrivenSlotCatalog reads these entries and calls
 * SlotRegistry::RegisterSlot() for each one.
 *
 * Example JSON slot entry:
 * @code
 * {
 *     "slot_name": "vehicle/hmac-256",
 *     "algorithm": "HMAC-SHA256",
 *     "provider_names": ["OPENSSL"],
 *     "allowed_operations": "MAC",
 *     "access_policy": { "allowed_uids": [0, 1000] },
 *     "deployment_path": "/opt/crypto/deploy/vehicle_hmac_256.kv",
 *     "deployment_format": "kv"
 * }
 * @endcode
 */
class KeyConfig
{
  public:
    /// @brief A single key slot definition from the configuration source.
    struct KeySlotEntry
    {
        std::string slot_name;
        std::string algorithm;
        /// @brief Ordered list of provider IDs. Index 0 is the primary (sole writer).
        /// Secondary providers may read/load the key via cross-provider transfer.
        std::vector<std::string> provider_names;
        std::string allowed_operations;            ///< String representation (e.g., "MAC", "ENCRYPT|DECRYPT")
        std::vector<uint32_t> allowed_uids;        ///< UIDs permitted to read/load from the slot
        std::vector<uint32_t> allowed_write_uids;  ///< UIDs permitted to write/generate into the slot
        /// @brief Absolute path to the deployment descriptor file.
        std::string deployment_path;
        /// @brief Format of the deployment descriptor (default "kv").
        std::string deployment_format{"kv"};
    };

    /// @brief Per-application resource ID to slot name mapping.
    ///
    /// Applications reference keys by portable application-local names
    /// (e.g., "signing_key") rather than hardcoded daemon slot names
    /// (e.g., "vehicle/rsa-2048"). Each application delivers a small set of
    /// entries that map its local names to actual daemon slot names.
    ///
    /// The daemon's SlotRegistry stores these mappings and resolves them
    /// transparently during ResolveResource IPC calls.
    struct AppResourceEntry
    {
        uint32_t uid;                 ///< UID of the application that owns this mapping
        std::string app_resource_id;  ///< Application-local resource name
        std::string slot_name;        ///< Actual slot name registered in the daemon registry
    };

    KeyConfig() = default;

    /// @brief Add a key slot definition (called by parser).
    void AddSlotEntry(KeySlotEntry entry)
    {
        m_slot_entries.push_back(std::move(entry));
    }

    /// @brief Get all parsed key slot definitions.
    const std::vector<KeySlotEntry>& GetSlotEntries() const
    {
        return m_slot_entries;
    }

    /// @brief Add an application resource mapping entry (called by parser).
    void AddAppResourceEntry(AppResourceEntry entry)
    {
        m_app_resource_entries.push_back(std::move(entry));
    }

    /// @brief Get all per-application resource ID mappings.
    const std::vector<AppResourceEntry>& GetAppResourceEntries() const
    {
        return m_app_resource_entries;
    }

    /// @brief Path to the JSON key slot manifest file (optional).
    ///
    /// If non-empty, ConfigDrivenSlotCatalog reads this file during Load().
    /// If empty, only the entries added via AddSlotEntry() are used.
    void SetManifestPath(const std::string& path)
    {
        m_manifest_path = path;
    }

    const std::string& GetManifestPath() const
    {
        return m_manifest_path;
    }

  private:
    std::vector<KeySlotEntry> m_slot_entries;
    std::vector<AppResourceEntry> m_app_resource_entries;
    std::string m_manifest_path;
};

/// @brief Type alias: PKCS#11 config is owned by the pkcs11 provider subsystem.
///
/// config.hpp exposes it under the config namespace for backward-compatible use;
/// the full definition lives in pkcs11_token_config.hpp.
using Pkcs11Config = ::score::crypto::daemon::provider::pkcs11::Pkcs11Config;

/// @brief Type alias: Score-provider config is owned by the score_provider subsystem.
///
/// config.hpp exposes it under the config namespace for consistent access;
/// the full definition lives in score_provider_config.hpp.
using ScoreProviderConfig = ::score::crypto::daemon::provider::score_provider::ScoreProviderConfig;

/**
 * @brief Certificate management configuration section (placeholder for future)
 */
class CertificateConfig
{
  public:
    CertificateConfig() = default;
    // Add methods as needed
};

/**
 * @brief Top-level configuration class
 *
 * Aggregates all configuration sections and provides access to them.
 * Components receive const reference to Config and access sub-sections via getter methods.
 *
 * Example usage:
 *   Config config;
 *   config.ParseEnvironment();
 *   config.ParseCommandLine(argc, argv);
 *
 *   // Components use it:
 *   void SomeComponent::Initialize(const Config& config) {
 *       auto threads = config.GetIPCConfig().GetNumOfIPCThreads();
 *   }
 */
class Config
{
  public:
    Config() = default;
    ~Config() = default;

    // Delete copy/move - single instance managed by main()
    Config(const Config&) = delete;
    Config& operator=(const Config&) = delete;
    Config(Config&&) = delete;
    Config& operator=(Config&&) = delete;

    /**
     * @brief Parse configuration from environment variables
     * @param env Optional environment map for testing. If empty, reads from actual environment.
     * @return true if parsing succeeded, false on error
     */
    bool ParseEnvironment(const std::map<std::string, std::string>& env = {});

    /**
     * @brief Parse configuration from command line arguments
     * @param argc Argument count
     * @param argv Argument values
     * @return true if parsing succeeded, false on error
     */
    bool ParseCommandLine(int argc, char** argv);

    /**
     * @brief Parse configuration (like flatbuffer)
     * @param none
     * @return true if parsing succeeded, false on error
     */
    bool ParseConfig();

    /**
     * @brief Validate all configuration sections
     * @return true if all sections are valid
     */
    bool Validate() const;

    // Const access for components (read-only)
    const IPCConfig& GetIPCConfig() const
    {
        return m_ipc;
    }
    const ProviderConfig& GetProviderConfig() const
    {
        return m_provider;
    }
    const ProviderInitConfig& GetProviderInitConfig() const
    {
        return m_provider_init;
    }
    const GeneralConfig& GetGeneralConfig() const
    {
        return m_general;
    }
    const KeyConfig& GetKeyConfig() const
    {
        return m_key;
    }
    const CertificateConfig& GetCertificateConfig() const
    {
        return m_certificate;
    }
    const Pkcs11Config& GetPkcs11Config() const
    {
        return m_pkcs11;
    }
    const ScoreProviderConfig& GetScoreProviderConfig() const
    {
        return m_score_provider;
    }

    // Non-const access for main()/parsers (can modify)
    IPCConfig& GetIPCConfig()
    {
        return m_ipc;
    }
    ProviderConfig& GetProviderConfig()
    {
        return m_provider;
    }
    GeneralConfig& GetGeneralConfig()
    {
        return m_general;
    }
    KeyConfig& GetKeyConfig()
    {
        return m_key;
    }
    CertificateConfig& GetCertificateConfig()
    {
        return m_certificate;
    }
    Pkcs11Config& GetPkcs11Config()
    {
        return m_pkcs11;
    }
    ScoreProviderConfig& GetScoreProviderConfig()
    {
        return m_score_provider;
    }

  private:
    IPCConfig m_ipc;
    ProviderConfig m_provider;
    ProviderInitConfig m_provider_init;
    GeneralConfig m_general;
    KeyConfig m_key;
    CertificateConfig m_certificate;
    Pkcs11Config m_pkcs11;
    ScoreProviderConfig m_score_provider;

    // Helper methods
    std::string GetEnvVar(const char* name, const std::map<std::string, std::string>& env) const;
    bool ParseStringArg(const std::string& arg,
                        const std::string& value,
                        const std::string& option,
                        std::string& target);
    bool ParseUint32Arg(const std::string& arg, const std::string& value, const std::string& option, uint32_t& target);
    bool ParseUint16Arg(const std::string& arg, const std::string& value, const std::string& option, uint16_t& target);
};

}  // namespace score::crypto::daemon::config

#endif  // SCORE_CRYPTO_DAEMON_CONFIG_CONFIG_HPP

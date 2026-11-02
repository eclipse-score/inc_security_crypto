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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CONFIG_INC_CONFIG_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CONFIG_INC_CONFIG_HPP

#include "score/crypto/src/daemon/common/types.hpp"
#ifdef SCORE_CRYPTO_PKCS11_BACKEND_ENABLED
#include "score/crypto/src/daemon/provider/pkcs11/pkcs11_token_config.hpp"
#endif
#ifdef SCORE_CRYPTO_SCORE_BACKEND_ENABLED
#include "score/crypto/src/daemon/provider/score_provider/score_provider_config.hpp"
#endif

#include <array>
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

// TODO: Need to move the individual configs into their respective components (dependency inversion)
// The config component shall be demanded to fulfill the needs of the components not vice versa.

namespace score::crypto::daemon::config
{

class ConfigFile;

// Configuration environment variable and default paths
/// @brief Environment variable name for the crypto stack configuration file.
///
/// The file is a binary FlatBuffers (.bin) file compiled by the build-time
/// ``flatc -b`` genrule. ParseConfig() populates both the key slot
/// configuration and the certificate management configuration from the same
/// file.

constexpr std::string_view CRYPTO_CONFIG_FILE_ENV = "CRYPTO_CONFIG_FILE";

constexpr uint16_t SERVER_PORT_DEFAULT = 50051;  ///< Default server port for IPC communication

constexpr uint32_t MAX_SESSIONS = 100U;                      ///< Maximum number of concurrent sessions allowed
constexpr uint32_t MAX_EPHEMERAL_KEYS_PER_CONNECTION = 32U;  ///< Per-connection ephemeral key limit
constexpr uint32_t MAX_LOADED_KEYS_PER_CONNECTION = 16U;     ///< Per-connection loaded-from-slot key limit
constexpr uint64_t MAX_TOTAL_KEY_MATERIAL_BYTES = 4UL * 1024U * 1024U;  ///< Global 4 MiB cap

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
    /// Maximum ephemeral keys allowed per client connection.
    uint32_t max_ephemeral_keys_per_connection{MAX_EPHEMERAL_KEYS_PER_CONNECTION};
    /// Maximum key slots that may be loaded per client connection.
    uint32_t max_loaded_keys_per_connection{MAX_LOADED_KEYS_PER_CONNECTION};
    /// Maximum aggregate key material size allowed by this policy, in bytes.
    uint64_t max_total_key_material_bytes{MAX_TOTAL_KEY_MATERIAL_BYTES};
};

/**
 * @brief IPC/Communication configuration section
 */
class IPCConfig
{
  public:
    IPCConfig() = default;

    /// @brief Return the number of IPC worker threads.
    /// @return The configured thread count.
    uint32_t GetNumOfIPCThreads() const noexcept
    {
        return m_num_ipc_threads;
    }

    /// @brief Return the address on which the IPC server listens.
    /// @return The configured server address.
    const std::string& GetServerAddress() const noexcept
    {
        return m_server_address;
    }

    /// @brief Return the IPC server port.
    /// @return The configured server port.
    uint16_t GetServerPort() const noexcept
    {
        return m_server_port;
    }

    /// @brief Set the number of IPC worker threads.
    /// @param threads Number of threads to configure.
    void SetNumOfIPCThreads(uint32_t threads)
    {
        m_num_ipc_threads = threads;
    }

    /// @brief Set the address on which the IPC server listens.
    /// @param address Server address to configure.
    void SetServerAddress(const std::string& address)
    {
        m_server_address = address;
    }

    /// @brief Set the IPC server port.
    /// @param port Server port to configure.
    void SetServerPort(uint16_t port)
    {
        m_server_port = port;
    }

  private:
    uint32_t m_num_ipc_threads = 4;
    std::string m_server_address = "0.0.0.0";
    uint16_t m_server_port = SERVER_PORT_DEFAULT;
};

/**
 * @brief Provider configuration - contains metadata for adding a new provider
 *
 * This structure holds the necessary information to create and initialize a
 * provider. Providers are identified by their ProviderName and can be categorized
 * by CryptoProviderType. The actual provider instance creation is handled by
 * the factory implementation, which can be easily extended to support new
 * provider types.
 */
struct ProviderConfig
{
    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    common::ProviderName providerName;        ///< Human-readable provider identifier
    common::CryptoProviderType cryptoType{};  ///< Functional category
    bool enabled{true};                       ///< Whether this provider should be used
    bool required{false};                     ///< Whether startup must provide this provider
    ResourceQuotaPolicy quota_policy{};       ///< Per-provider quota policy override
    // NOLINTEND(misc-non-private-member-variables-in-classes)

    ProviderConfig() = default;

    /// @brief Construct provider metadata with explicit identity and state.
    /// @param name Human-readable provider identifier.
    /// @param cryptoType Functional provider category.
    /// @param enabled Whether the provider is enabled for initialization.
    /// @param required Whether startup fails if the provider is unavailable.
    ProviderConfig(const common::ProviderName& name,
                   common::CryptoProviderType cryptoType,
                   bool enabled = true,
                   bool required = false)
        : providerName(name), cryptoType(cryptoType), enabled(enabled), required(required)
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
    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    std::vector<ProviderConfig> providers;  ///< List of providers to initialize
    std::unordered_map<common::CryptoProviderType, common::ProviderName>
        typeToProviderName;  ///< Mapping of provider types to their default
                             ///< provider name
    // NOLINTEND(misc-non-private-member-variables-in-classes)

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
     * @param providerName The provider name to use for this type
     */
    void SetDefaultProviderForType(common::CryptoProviderType cryptoType, const common::ProviderName& providerName)
    {
        typeToProviderName[cryptoType] = providerName;
    }
};

/**
 * @brief General daemon configuration section
 */
class GeneralConfig
{
  public:
    GeneralConfig() = default;

    /// @brief Return the configured daemon log level.
    /// @return The log-level string.
    const std::string& GetLogLevel() const noexcept
    {
        return m_log_level;
    }

    /// @brief Return the maximum number of concurrent sessions.
    /// @return The configured session limit.
    uint32_t GetMaxSessions() const noexcept
    {
        return m_max_sessions;
    }

    /// @brief Return the daemon-wide resource quota policy.
    /// @return The configured quota policy.
    const ResourceQuotaPolicy& GetQuotaPolicy() const noexcept
    {
        return m_quota_policy;
    }

    /// @brief Set the daemon log level.
    /// @param level Log-level string to configure.
    void SetLogLevel(const std::string& level)
    {
        m_log_level = level;
    }
    /// @brief Set the maximum number of concurrent sessions.
    /// @param max Session limit to configure.
    void SetMaxSessions(uint32_t max)
    {
        m_max_sessions = max;
    }
    /// @brief Set the daemon-wide resource quota policy.
    /// @param quota_policy Quota policy to configure.
    void SetQuotaPolicy(const ResourceQuotaPolicy& quota_policy)
    {
        m_quota_policy = quota_policy;
    }

  private:
    std::string m_log_level = "info";
    uint32_t m_max_sessions = MAX_SESSIONS;
    ResourceQuotaPolicy m_quota_policy{};
};

/**
 * @brief Key management configuration section
 *
 * Stores key slot definitions parsed from the daemon's binary FlatBuffers
 * configuration source. Each entry describes a persistent key slot:
 * its human-readable name, algorithm, owning provider, access policy, and
 * a deployment path that points to the external deployment descriptor.
 *
 * At daemon startup, a ConfigDrivenSlotCatalog reads these entries and calls
 * SlotRegistry::RegisterSlot() for each one.
 *
 * Example slot entry:
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
        /// Human-readable name used to identify this key slot.
        std::string slot_name;
        /// Algorithm configured for keys stored in this slot.
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
    struct AppKeySlotMapping
    {
        uint32_t uid;                 ///< UID of the application that owns this mapping
        std::string app_resource_id;  ///< Application-local resource name
        std::string slot_name;        ///< Actual key slot name registered in the daemon registry
    };

    KeyConfig() = default;

    /// @brief Add a key slot definition (called by parser).
    /// @param entry Key slot definition to add.
    void AddSlotEntry(KeySlotEntry entry)
    {
        m_slot_entries.push_back(std::move(entry));
    }

    /// @brief Get all parsed key slot definitions.
    /// @return The configured key slot definitions.
    const std::vector<KeySlotEntry>& GetSlotEntries() const noexcept
    {
        return m_slot_entries;
    }

    /// @brief Add an application resource mapping entry (called by parser).
    /// @param entry Application-to-key-slot mapping to add.
    void AddAppKeySlotMapping(AppKeySlotMapping entry)
    {
        m_app_key_slot_mappings.push_back(std::move(entry));
    }

    /// @brief Get all per-application key slot resource ID mappings.
    /// @return The configured application-to-key-slot mappings.
    const std::vector<AppKeySlotMapping>& GetAppKeySlotMappings() const noexcept
    {
        return m_app_key_slot_mappings;
    }

    /// @brief Path to an optional key slot manifest used by catalog tooling.
    ///
    /// If non-empty, ConfigDrivenSlotCatalog reads this file during Load().
    /// If empty, only the entries added via AddSlotEntry() are used.
    /// @param path Manifest path, or an empty string to disable manifest loading.
    void SetManifestPath(const std::string& path)
    {
        m_manifest_path = path;
    }

    /// @brief Return the optional key slot manifest path.
    /// @return The configured path, or an empty string when no manifest is used.
    const std::string& GetManifestPath() const noexcept
    {
        return m_manifest_path;
    }

  private:
    std::vector<KeySlotEntry> m_slot_entries;
    std::vector<AppKeySlotMapping> m_app_key_slot_mappings;
    std::string m_manifest_path;
};

#ifdef SCORE_CRYPTO_PKCS11_BACKEND_ENABLED
/// @brief Type alias: PKCS#11 config is owned by the pkcs11 provider subsystem.
///
/// config.hpp exposes it under the config namespace for backward-compatible use;
/// the full definition lives in pkcs11_token_config.hpp.
using Pkcs11Config = ::score::crypto::daemon::provider::pkcs11::Pkcs11Config;
#endif

#ifdef SCORE_CRYPTO_SCORE_BACKEND_ENABLED
/// @brief Type alias: Score-provider config is owned by the score_provider subsystem.
///
/// config.hpp exposes it under the config namespace for consistent access;
/// the full definition lives in score_provider_config.hpp.
using ScoreProviderConfig = ::score::crypto::daemon::provider::score_provider::ScoreProviderConfig;
#endif

/**
 * @brief Certificate management configuration section
 *
 * Stores certificate slot and trust store definitions parsed from the daemon's
 * configuration source.
 *
 * At daemon startup, a ConfigDrivenSlotCatalog reads CertSlotEntry items and
 * registers each slot with the CertSlotRegistry. TrustStoreEntry items are
 * consumed by TrustStoreManager during initialisation.
 */
class CertificateConfig
{
  public:
    /// Membership ownership and change-acceptance policy for a trust-store slot.
    enum class TrustStoreMemberKind : uint8_t
    {
        /// Externally managed slot. The trust store does not add or remove this
        /// membership through its runtime membership operations.
        kSharedStatic = 0U,

        /// Slot owned by the trust store, which may populate or clear it through
        /// trust-store operations.
        kExclusiveMutable = 1U,

        /// Externally managed slot tracked by fingerprint. An unexpected
        /// content change disables the member until it is acknowledged.
        kConditionalExternal = 2U,
    };

    /// Integrity enforcement for the content a certificate slot stores.
    enum class IntegrityPolicy : uint8_t
    {
        /// No integrity check is applied to the stored content.
        kDisabled = 0U,

        /// The stored content must pass the integrity check the deployment defines before it is used.
        /// The check is deployment-specific and may cover certificate content, CRL data, or other material.
        kRequired = 1U,
    };

    /// Initial policy for conditional members that have no persisted state.
    enum class ConditionalSlotInitialization : uint8_t
    {
        /// Enable the member and accept its current certificate fingerprint. When the store has a
        /// deployment path the acceptance is persisted first. A memory-only store (no deployment
        /// path) keeps it only for the life of the process, so each restart accepts whatever
        /// certificate the slot holds at that time.
        kEnableAndAcceptCurrent = 0U,

        /// Disable the member until its current fingerprint is acknowledged.
        kDisableUntilAccepted = 1U,
    };

    /// A trust-store member reference and its ownership policy.
    struct TrustStoreMemberEntry
    {
        /// Name of a certificate slot defined in the certificate configuration.
        std::string slot_name;

        /// Ownership and change-acceptance policy for the referenced slot.
        TrustStoreMemberKind kind{TrustStoreMemberKind::kSharedStatic};
    };

    /// @brief Per-application resource ID to certificate slot name mapping.
    ///
    /// Applications reference cert slots by portable local names rather than
    /// daemon slot names.
    struct AppCertSlotMapping
    {
        uint32_t uid;                 ///< UID of the application that owns this mapping
        std::string app_resource_id;  ///< Application-local resource name
        std::string slot_name;        ///< Actual cert slot name registered in the CertSlotRegistry
    };

    /// @brief Per-application resource ID to trust store name mapping.
    ///
    /// Applications reference trust stores by portable local names rather than
    /// daemon trust store names.
    struct AppTrustStoreMapping
    {
        uint32_t uid;                  ///< UID of the application that owns this mapping
        std::string app_resource_id;   ///< Application-local resource name
        std::string trust_store_name;  ///< Actual trust store name registered in the daemon
    };

    /// @brief A single certificate slot definition from the configuration source.
    struct CertSlotEntry
    {
        /// Human-readable name used to identify this certificate slot.
        std::string slot_name;
        /// @brief Storage backend for this slot. Immutable after startup.
        ///
        /// Identifies which ICertSlotHandler implementation manages physical storage.
        /// "DEFAULT" → FileBackedSlotHandler.
        /// Any other value is a provider name; that provider supplies the
        /// ICertSlotHandler implementation.
        /// Backend-specific locators (file path, token label) live in the deployment descriptor.
        std::string storage_backend{"DEFAULT"};
        std::vector<uint32_t> allowed_uids;        ///< UIDs permitted to read/load from the slot
        std::vector<uint32_t> allowed_write_uids;  ///< UIDs permitted to write into the slot
        /// @brief Absolute path to the deployment descriptor file.
        std::string deployment_path;
        /// @brief Deployment descriptor format identifier. Defaults to "kv".
        std::string deployment_format{"kv"};
        /// @brief Integrity enforcement policy. Defaults to kDisabled.
        ///
        /// kRequired: the stored content must pass the deployment's integrity check before use.
        /// The policy lives here (out-of-band from the descriptor) so a compromised
        /// descriptor cannot switch the check off.
        IntegrityPolicy integrity_policy{IntegrityPolicy::kDisabled};
    };

    /// @brief A single trust store definition from the configuration source.
    ///
    /// Trust stores reference typed certificate-slot memberships; shared-static
    /// slots can back multiple named trust stores.
    struct TrustStoreEntry
    {
        /// Name used to identify this trust store in daemon configuration.
        std::string store_name;
        /// @brief Certificate-slot memberships and their trust-store policy.
        std::vector<TrustStoreMemberEntry> members;
        /// @brief Default policy for conditional members without persisted state.
        ConditionalSlotInitialization conditional_slot_initialization{
            ConditionalSlotInitialization::kDisableUntilAccepted};
        std::vector<uint32_t> allowed_uids;        ///< UIDs permitted to query this store
        std::vector<uint32_t> allowed_write_uids;  ///< UIDs permitted to mutate this store
        /// @brief Absolute path for persisting trust store state.
        std::string deployment_path;
        /// @brief Deployment descriptor format identifier. Defaults to "kv".
        std::string deployment_format{"kv"};
    };

    CertificateConfig() = default;

    /// @brief Set the provider used as the daemon-wide certificate parser.
    ///
    /// When empty, the provider manager's kCertManagement default is used.
    /// This is independent of each certificate slot's storage backend.
    /// @param provider_name Provider name to configure, or empty to use the default.
    void SetParserProviderName(const common::ProviderName& provider_name)
    {
        m_parser_provider_name = provider_name;
    }

    /// @brief Get the explicitly configured daemon-wide certificate parser provider.
    ///
    /// An empty value means the provider manager's kCertManagement default is used.
    /// @return The configured provider name, or empty when the default is used.
    const common::ProviderName& GetParserProviderName() const noexcept
    {
        return m_parser_provider_name;
    }

    /// @brief Add a certificate slot definition (called by parser).
    /// @param entry Certificate slot definition to add.
    void AddSlotEntry(CertSlotEntry entry)
    {
        m_slot_entries.push_back(std::move(entry));
    }

    /// @brief Get all parsed certificate slot definitions.
    /// @return The configured certificate slot definitions.
    const std::vector<CertSlotEntry>& GetSlotEntries() const noexcept
    {
        return m_slot_entries;
    }

    /// @brief Add a trust store definition (called by parser).
    /// @param entry Trust store definition to add.
    void AddTrustStoreEntry(TrustStoreEntry entry)
    {
        m_trust_store_entries.push_back(std::move(entry));
    }

    /// @brief Add an application-to-certificate-slot mapping.
    /// @param entry Application resource mapping to add.
    void AddAppCertSlotMapping(AppCertSlotMapping entry)
    {
        m_app_cert_slot_mappings.push_back(std::move(entry));
    }

    /// @brief Get all application-to-certificate-slot mappings.
    /// @return The configured application resource mappings.
    const std::vector<AppCertSlotMapping>& GetAppCertSlotMappings() const noexcept
    {
        return m_app_cert_slot_mappings;
    }

    /// @brief Add an application-to-trust-store mapping.
    /// @param entry Application resource mapping to add.
    void AddAppTrustStoreMapping(AppTrustStoreMapping entry)
    {
        m_app_trust_store_mappings.push_back(std::move(entry));
    }

    /// @brief Get all application-to-trust-store mappings.
    /// @return The configured application resource mappings.
    const std::vector<AppTrustStoreMapping>& GetAppTrustStoreMappings() const noexcept
    {
        return m_app_trust_store_mappings;
    }

    /// @brief Get all parsed trust store definitions.
    /// @return The configured trust store definitions.
    const std::vector<TrustStoreEntry>& GetTrustStoreEntries() const noexcept
    {
        return m_trust_store_entries;
    }

  private:
    common::ProviderName m_parser_provider_name;
    std::vector<CertSlotEntry> m_slot_entries;
    std::vector<TrustStoreEntry> m_trust_store_entries;
    std::vector<AppCertSlotMapping> m_app_cert_slot_mappings;
    std::vector<AppTrustStoreMapping> m_app_trust_store_mappings;
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
     * @brief Parse the crypto stack configuration from the resolved config file.
     *
     * When no config file is found on the default paths, the configuration stays empty and
     * this is not an error. A path given by CRYPTO_CONFIG_FILE that does not exist, or a file
     * that cannot be read or parsed, is an error.
     *
     * @return true if the configuration was loaded or no default file was found; false on error
     */
    bool ParseConfig();

    /**
     * @brief Validate all configuration sections
     * @return true if all sections are valid; false if any section is invalid
     */
    bool Validate() const;

    // Const access for components (read-only)
    /// @brief Return the IPC configuration (read-only).
    /// @return The IPC configuration section.
    const IPCConfig& GetIPCConfig() const noexcept
    {
        return m_ipc;
    }
    /// @brief Return the provider configuration (read-only).
    /// @return The provider configuration section.
    const ProviderConfig& GetProviderConfig() const noexcept
    {
        return m_provider;
    }
    /// @brief Return the provider initialization configuration (read-only).
    /// @return The provider initialization section.
    const ProviderInitConfig& GetProviderInitConfig() const noexcept
    {
        return m_provider_init;
    }
    /// @brief Return the general daemon configuration (read-only).
    /// @return The general configuration section.
    const GeneralConfig& GetGeneralConfig() const noexcept
    {
        return m_general;
    }
    /// @brief Return the key management configuration (read-only).
    /// @return The key configuration section.
    const KeyConfig& GetKeyConfig() const noexcept
    {
        return m_key;
    }
    /// @brief Return the certificate management configuration (read-only).
    /// @return The certificate configuration section.
    const CertificateConfig& GetCertificateConfig() const noexcept
    {
        return m_certificate;
    }
    /// @brief Whether the key management section was present in the configuration file.
    /// @return true if the section was present and loaded.
    bool IsKeyManagementEnabled() const noexcept
    {
        return m_key_management_enabled;
    }
    /// @brief Whether the certificate management section was present in the configuration file.
    /// @return true if the section was present and loaded.
    bool IsCertManagementEnabled() const noexcept
    {
        return m_cert_management_enabled;
    }

#ifdef SCORE_CRYPTO_PKCS11_BACKEND_ENABLED
    /// @brief Return the PKCS#11 provider configuration (read-only).
    /// @return The PKCS#11 configuration section.
    const Pkcs11Config& GetPkcs11Config() const noexcept
    {
        return m_pkcs11;
    }
#endif

#ifdef SCORE_CRYPTO_SCORE_BACKEND_ENABLED
    /// @brief Return the Score provider configuration (read-only).
    /// @return The Score provider configuration section.
    const ScoreProviderConfig& GetScoreProviderConfig() const noexcept
    {
        return m_score_provider;
    }
#endif

    // Non-const access for main()/parsers (can modify)
    /// @brief Return mutable access to the IPC configuration.
    /// @return The IPC configuration section.
    IPCConfig& GetIPCConfig()
    {
        return m_ipc;
    }
    /// @brief Return mutable access to the provider configuration.
    /// @return The provider configuration section.
    ProviderConfig& GetProviderConfig()
    {
        return m_provider;
    }
    /// @brief Return mutable access to the general daemon configuration.
    /// @return The general configuration section.
    GeneralConfig& GetGeneralConfig()
    {
        return m_general;
    }
    /// @brief Return mutable access to the key management configuration.
    /// @return The key configuration section.
    KeyConfig& GetKeyConfig()
    {
        return m_key;
    }
    /// @brief Return mutable access to the certificate management configuration.
    /// @return The certificate configuration section.
    CertificateConfig& GetCertificateConfig()
    {
        return m_certificate;
    }

#ifdef SCORE_CRYPTO_PKCS11_BACKEND_ENABLED
    /// @brief Return mutable access to the PKCS#11 provider configuration.
    /// @return The PKCS#11 configuration section.
    Pkcs11Config& GetPkcs11Config()
    {
        return m_pkcs11;
    }
#endif

#ifdef SCORE_CRYPTO_SCORE_BACKEND_ENABLED
    /// @brief Return mutable access to the Score provider configuration.
    /// @return The Score provider configuration section.
    ScoreProviderConfig& GetScoreProviderConfig()
    {
        return m_score_provider;
    }
#endif

  private:
    IPCConfig m_ipc;
    ProviderConfig m_provider;
    ProviderInitConfig m_provider_init;
    GeneralConfig m_general;
    KeyConfig m_key;
    CertificateConfig m_certificate;
    bool m_key_management_enabled{false};
    bool m_cert_management_enabled{false};
#ifdef SCORE_CRYPTO_PKCS11_BACKEND_ENABLED
    Pkcs11Config m_pkcs11;
#endif
#ifdef SCORE_CRYPTO_SCORE_BACKEND_ENABLED
    ScoreProviderConfig m_score_provider;
#endif

    // ---------------------------------------------------------------------------
    // Per-component config section parsers (called from ParseConfig).
    //
    // Each method loads one component's section and sets that component's
    // enabled flag. To add a new component (e.g. provider management), add a
    // new private method here, give it an enabled flag, and call it from
    // ParseConfig().
    //
    // An absent section sets the flag to false and returns true. A present
    // section that cannot be parsed returns false.
    // ---------------------------------------------------------------------------

    /// Populate m_key from the key_slot_config section; sets m_key_management_enabled.
    bool ParseKeyManagementSection(const ConfigFile& file);

    /// Populate m_certificate from the cert_slot_config section; sets m_cert_management_enabled.
    bool ParseCertManagementSection(const ConfigFile& file);

    // ---------------------------------------------------------------------------
    // Low-level argument / environment helpers
    // ---------------------------------------------------------------------------

    /// @brief Look up an environment variable.
    ///
    /// When @p env is non-empty it is used instead of the process environment, so tests can
    /// supply their own values.
    /// @param name Variable name.
    /// @param env  Override map; empty means read the process environment.
    /// @return The value, or an empty string if the variable is not set.
    std::string GetEnvVar(const char* name, const std::map<std::string, std::string>& env) const;

    /// @brief Parse a string-valued command-line option.
    ///
    /// Not implemented yet: always returns false and leaves @p target unchanged.
    /// @param arg    The argument as it appeared on the command line.
    /// @param value  The value to parse.
    /// @param option The option name the value belongs to.
    /// @param target Receives the parsed value on success.
    /// @return true if the argument was recognised and parsed.
    bool ParseStringArg(const std::string& arg,
                        const std::string& value,
                        const std::string& option,
                        std::string& target);

    /// @brief Parse an unsigned 32-bit command-line option.
    ///
    /// Not implemented yet: always returns false and leaves @p target unchanged.
    /// @param arg    The argument as it appeared on the command line.
    /// @param value  The value to parse.
    /// @param option The option name the value belongs to.
    /// @param target Receives the parsed value on success.
    /// @return true if the argument was recognised and parsed.
    bool ParseUint32Arg(const std::string& arg, const std::string& value, const std::string& option, uint32_t& target);

    /// @brief Parse an unsigned 16-bit command-line option.
    ///
    /// Not implemented yet: always returns false and leaves @p target unchanged.
    /// @param arg    The argument as it appeared on the command line.
    /// @param value  The value to parse.
    /// @param option The option name the value belongs to.
    /// @param target Receives the parsed value on success.
    /// @return true if the argument was recognised and parsed.
    bool ParseUint16Arg(const std::string& arg, const std::string& value, const std::string& option, uint16_t& target);
};

}  // namespace score::crypto::daemon::config

#endif  // SCORE_CRYPTO_SRC_DAEMON_CONFIG_INC_CONFIG_HPP

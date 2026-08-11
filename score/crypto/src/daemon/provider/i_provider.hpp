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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_I_PROVIDER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_I_PROVIDER_HPP

#include "score/crypto/src/daemon/common/types.hpp"
#include <cstdint>
#include <memory>

// Forward declarations — full headers are only pulled in by .cpp files.
namespace score::crypto::daemon::provider::handler
{
class ICryptoHandlerFactory;
}  // namespace score::crypto::daemon::provider::handler

namespace score::crypto::daemon::key_management
{
class IKeyFactory;
class IKeySlotHandler;
class KeyManagementService;
struct KeySlotConfig;
}  // namespace score::crypto::daemon::key_management

namespace score::crypto::daemon::data_plane
{
class IShmFactory;
}  // namespace score::crypto::daemon::data_plane

namespace score::crypto::daemon::provider
{

class ProviderManager;  // Forward declaration

/// @brief Initialization context passed to IProvider::Initialize()
///
/// Contains the numeric provider ID (assigned by ProviderManager) and
/// the human-readable provider name (from configuration).
struct ProviderInitContext
{
    common::ProviderId numeric_id;  ///< Assigned by ProviderManager (0, 1, 2, …)
    common::ProviderName name;      ///< Human-readable name from config/factory
};

/// @brief Core provider interface — lifecycle, identity, and capability accessors.
///
/// Concrete providers subclass IProvider for lifecycle management (Initialize,
/// Shutdown) and identification (GetProviderId, GetProviderName).  Functional
/// capabilities are expressed through optional virtual accessors with safe
/// default return values (nullptr / no-op).  A provider overrides only the
/// methods it supports.
///
/// ### Single-Provider Binding
/// Keys and contexts are bound to a single provider for the lifetime of the context.
/// The `KeySlotConfig::provider_ids` list specifies which providers are compatible
/// with a key slot; however, only the primary (first) provider is used for
/// context-level operations. Providers never need to know about each other.
class IProvider
{
  public:
    virtual ~IProvider() = default;

    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------

    /// @brief Initialize the provider with assigned ID and name.
    /// @param ctx Initialization context containing numeric_id and name
    /// @return true on success, false on failure
    virtual bool Initialize(const ProviderInitContext& ctx) = 0;

    /// @brief Shutdown the provider and release all resources.
    virtual void Shutdown() = 0;

    /// @brief Return whether the provider has been successfully initialized.
    ///
    /// @return true if Initialize() returned success, false otherwise
    [[nodiscard]] virtual bool IsInitialized() const = 0;

    /// @brief Return the provider's unique numeric identifier.
    /// @return ProviderId (uint16_t) assigned by ProviderManager
    virtual common::ProviderId GetProviderId() const = 0;

    /// @brief Return the provider's human-readable name.
    /// @return ProviderName (string) from configuration or factory
    virtual const common::ProviderName& GetProviderName() const = 0;

    // -----------------------------------------------------------------------
    // Crypto capability (override if supported — default returns nullptr)
    // -----------------------------------------------------------------------

    /// @brief Return the factory that creates per-algorithm crypto handlers.
    ///
    /// Returns nullptr if the provider does not support crypto operations.
    /// The factory is stateless and safe to call concurrently.
    virtual std::shared_ptr<handler::ICryptoHandlerFactory> GetCryptoHandlerFactory()
    {
        return nullptr;
    }

    // -----------------------------------------------------------------------
    // Key management capability (override if supported — defaults return nullptr)
    // -----------------------------------------------------------------------

    /// Return the provider's key factory (score-interface providers: OpenSSL, etc.).
    ///
    /// Returns nullptr for providers that do not implement IKeyFactory (e.g., PKCS#11
    /// which creates keys through Pkcs11KeyMgmtHandler which is both Handler and IKeyFactory).
    virtual std::shared_ptr<key_management::IKeyFactory> GetKeyFactory()
    {
        return nullptr;
    }

    /// @brief Return a key slot handler for the given slot configuration.
    ///
    /// Returns nullptr if the provider does not support key slot management.
    virtual std::shared_ptr<key_management::IKeySlotHandler> GetKeySlotHandler(
        const key_management::KeySlotConfig& /*config*/)
    {
        return nullptr;
    }

    /// @brief Inject the daemon-wide key management service.
    ///
    /// Called once at daemon startup before any handler is created.
    /// Providers that do not support key management may ignore this (default no-op).
    virtual void SetKeyManagementService(std::shared_ptr<key_management::KeyManagementService> /*service*/) {}

    // -----------------------------------------------------------------------
    // SHM capability (override if supported — default returns nullptr)
    // -----------------------------------------------------------------------

    /// @brief Return the provider's shared-memory factory.
    ///
    /// Returns nullptr if the provider does not supply its own SHM allocation
    virtual std::shared_ptr<data_plane::IShmFactory> GetShmFactory()
    {
        return nullptr;
    }

    // -----------------------------------------------------------------------
    // Capability advertisement
    // -----------------------------------------------------------------------

    /// @brief Report the functional capabilities this provider offers.
    ///
    /// Concrete providers MUST override this and return their full capability set
    /// explicitly. The default returns kNone so an unoverridden provider is never
    /// selected by GetProviderForCapability() — a silent miss is always preferable
    /// to a mis-routed operation. Derivation from accessor returns is intentionally
    /// avoided: as capability entry points evolve, heuristic derivation becomes
    /// incorrect.
    ///
    /// Used by ProviderManager::GetProviderForCapability() to pick a default
    /// provider for a functional area rather than by hardware/software category.
    [[nodiscard]] virtual common::ProviderCapability GetProviderCapabilities()
    {
        return common::ProviderCapability::kNone;
    }
};

}  // namespace score::crypto::daemon::provider

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_I_PROVIDER_HPP

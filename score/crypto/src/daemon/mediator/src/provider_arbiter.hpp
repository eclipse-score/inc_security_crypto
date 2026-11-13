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

#ifndef SCORE_CRYPTO_SRC_DAEMON_MEDIATOR_PROVIDER_ARBITER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_MEDIATOR_PROVIDER_ARBITER_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/algorithm_catalog.hpp"
#include "score/crypto/src/daemon/common/context/i_handler.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/key_management/core/key_management_service.hpp"
#include "score/crypto/src/daemon/provider/i_provider.hpp"
#include "score/crypto/src/daemon/provider/provider_manager.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>

namespace score::crypto::daemon::mediator
{

/// @brief Inputs the arbiter needs to choose a provider and create a handler.
struct ProviderSelectionRequest final
{
    std::uint64_t client_id{0U};                 ///< Client used to resolve the provider associated with a key node.
    std::optional<std::uint64_t> key_node_id{};  ///< Optional key node used to preserve provider affinity.
    std::string_view context_type{};             ///< Context type passed to the handler factory.
    std::optional<AlgorithmDescriptor> algorithm{};  ///< Algorithm descriptor; absent for key-management contexts.
    common::ProviderTypePreference provider{common::CryptoProviderType::DEFAULT,
                                            std::nullopt};  ///< Primary provider and optional fallback.
    common::ProviderCapability required_capability{
        common::ProviderCapability::kNone};  ///< Capability the selected provider must support.
};

/// @brief Selected provider and the handler it created.
struct ProviderHandlerSelection final
{
    std::shared_ptr<provider::IProvider> provider;         ///< Provider selected by the arbiter.
    score::crypto::daemon::common::Handler::Sptr handler;  ///< Handler created by the selected provider.
    bool used_fallback{false};                             ///< Whether selection used the fallback preference.
};

/// @brief Chooses a provider for a context and creates its handler.
///
/// The primary provider is tried first. The fallback is tried only when the primary is
/// unavailable or cannot create the handler, and only for the error codes that
/// `IsFallbackEligible` accepts. The same provider is never tried twice.
class ProviderArbiter final
{
  public:
    /// @brief Create an arbiter with provider lookup and optional key-affinity services.
    /// @param provider_manager Manager used to find providers by type, capability, or identifier.
    /// @param km_service Optional service used to resolve the provider associated with a key node.
    ProviderArbiter(provider::ProviderManager::Sptr provider_manager,
                    key_management::KeyManagementService::Sptr km_service) noexcept;

    /// @brief Select a provider and create its handler, trying eligible fallback preferences as needed.
    /// @param request Provider selection inputs and context details.
    /// @return The selected provider and handler, or the last provider/handler creation error.
    [[nodiscard]] score::crypto::Expected<ProviderHandlerSelection, score::crypto::CryptoErrorCode> Select(
        const ProviderSelectionRequest& request) const;

  private:
    /// @brief Resolve the provider for one candidate provider type.
    ///
    /// The provider that owns the referenced key takes precedence. Otherwise a DEFAULT type with a
    /// required capability resolves to the provider for that capability, and any other type to the
    /// provider registered for it.
    /// @param request Provider selection inputs.
    /// @param provider_type Candidate provider type being resolved.
    /// @return The provider, or the error that makes this candidate unusable.
    [[nodiscard]] score::crypto::Expected<std::shared_ptr<provider::IProvider>, score::crypto::CryptoErrorCode>
    ResolveProvider(const ProviderSelectionRequest& request, common::CryptoProviderType provider_type) const;

    provider::ProviderManager::Sptr m_provider_manager;
    key_management::KeyManagementService::Sptr m_km_service;
};

}  // namespace score::crypto::daemon::mediator

#endif  // SCORE_CRYPTO_SRC_DAEMON_MEDIATOR_PROVIDER_ARBITER_HPP

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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_SCORE_BACKEND_ADAPTER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_SCORE_BACKEND_ADAPTER_HPP

#include "score/crypto/src/daemon/provider/i_provider.hpp"

#include <functional>
#include <memory>
#include <string>

namespace score::crypto::daemon::provider::score_provider
{

/// @brief Provider creator metadata for a score provider backend.
///
/// Contains backend identification and a provider construction function.
/// ScoreProviderFactory uses this to create IProvider instances and
/// register them under the name and type from ScoreProviderEntry.
struct ProviderCreator
{
    /// Unique identifier for the backend (e.g., "openssl", "primula").
    /// Matched against ScoreProviderEntry::providerImpl during dispatch.
    std::string backend_id;

    /// Human-readable name for the backend (e.g., "OPENSSL", "PRIMULA").
    /// Used as the default providerName when populating ScoreProviderEntry via ParseConfig().
    std::string backend_name;

    /// Provider type string (e.g., "SOFTWARE", "HARDWARE", "SPECIALIZED").
    /// Used as the default providerType when populating ScoreProviderEntry via ParseConfig().
    std::string provider_type{"SOFTWARE"};

    /// Constructs and returns the concrete IProvider for this backend.
    /// Registration (name, type, ProviderManager) is handled by ScoreProviderFactory.
    std::function<std::unique_ptr<IProvider>()> create_provider;
};

/// @brief Interface for score provider backend adapters.
///
/// Each backend (OpenSSL, BoringSSL, mbedTLS) implements this interface to
/// expose a ProviderCreator. ScoreProviderFactory discovers active backends
/// at compile-time via backend/score_provider/active_backends_list.hpp and uses the creator
/// to construct IProvider instances; registration into ProviderManager is
/// handled by ScoreProviderFactory using config-driven name and type.
///
/// Example implementation:
/// @code
///   class OpenSSLBackendAdapter : public IBackendProviderAdapter {
///     public:
///       ProviderCreator GetProviderCreator() const override {
///           return {
///               .backend_id    = "openssl",
///               .backend_name  = "OPENSSL",
///               .provider_type = "SOFTWARE",
///               .create_provider = []() {
///                   return std::make_unique<OpenSSL>();
///               }
///           };
///       }
///   };
/// @endcode
class IBackendProviderAdapter
{
  public:
    virtual ~IBackendProviderAdapter() = default;

    /// @brief Returns the ProviderCreator for this backend.
    ///
    /// Called by ScoreProviderFactory per config entry to construct the
    /// IProvider. Name and type for registration come from ScoreProviderEntry.
    [[nodiscard]] virtual ProviderCreator GetProviderCreator() const = 0;

  protected:
    IBackendProviderAdapter() = default;
};

}  // namespace score::crypto::daemon::provider::score_provider

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_SCORE_BACKEND_ADAPTER_HPP

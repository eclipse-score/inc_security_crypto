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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_SLOT_SLOT_HANDLER_FACTORY_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_SLOT_SLOT_HANDLER_FACTORY_HPP

#include "score/crypto/src/daemon/cert_management/interfaces/i_cert_slot_handler.hpp"
#include "score/crypto/src/daemon/provider/cert_management/i_cert_parser.hpp"
#include "score/crypto/src/daemon/provider/provider_manager.hpp"

#include <memory>
#include <mutex>

namespace score::crypto::daemon::cert_management
{

/// @brief CertSlotHandlerFactory callable that resolves a slot's storage backend
///        ("DEFAULT" -> FileBackedSlotHandler, otherwise a named provider) on
///        every invocation.
///
/// Holds ProviderManager only via weak_ptr. CertSlotManager (owned transitively
/// by a provider through CertManagementService, e.g. OpenSSL::m_certManagementService)
/// stores this factory, so a strong ProviderManager::Sptr captured here would close
/// a reference cycle: ProviderManager -> provider -> CertManagementService ->
/// CertSlotManager -> this factory -> ProviderManager. A dead ProviderManager at
/// call time means the daemon is shutting down; operator() returns nullptr rather
/// than reviving ownership.
///
/// The certificate parser is resolved lazily and cached after the first successful
/// resolution — the kCertManagement-capable provider and its parser are fixed for
/// the daemon's lifetime once registered, so there is no reason to repeat the
/// provider lookup for every slot. A failed resolution (e.g. the provider has not
/// finished registering yet) is not cached and is retried on the next call.
///
/// Copyable: CertSlotHandlerFactory is a std::function, which requires its target
/// to be copy-constructible. The parser cache lives in a heap-allocated, mutex-guarded
/// ParserCache shared via shared_ptr, so every copy of a given SlotHandlerFactory
/// observes and contributes to the same cache.
class SlotHandlerFactory final
{
  public:
    /// @brief Construct the factory over a provider registry held only weakly.
    /// @param provider_manager Provider registry consulted to resolve the certificate
    ///        parser and, for non-"DEFAULT" backends, the owning provider's slot handler.
    explicit SlotHandlerFactory(provider::ProviderManager::Sptr provider_manager)
        : m_provider_manager{std::move(provider_manager)}, m_cache{std::make_shared<ParserCache>()}
    {
    }

    /// @brief Create a slot handler for the given slot configuration.
    /// @param slot Slot configuration; storage_backend selects FileBackedSlotHandler
    ///        ("DEFAULT") or the ICertSlotHandler implementation of a named provider.
    /// @return The constructed handler, or nullptr when the provider registry is gone,
    ///         the named backend provider cannot be found, or the provider declines to
    ///         produce a handler for the slot.
    [[nodiscard]] ICertSlotHandler::Sptr operator()(const CertSlotConfig& slot) const;

  private:
    /// @brief Mutex-guarded cache of the resolved certificate parser, shared by every
    ///        copy of the SlotHandlerFactory instance it was created from.
    struct ParserCache
    {
        std::mutex mutex;
        provider::cert_management::ICertParser::Sptr parser;
    };

    /// @brief Resolve the certificate parser from the kCertManagement-capable provider,
    ///        caching the result after the first successful resolution.
    /// @param provider_manager Locked provider registry for this call; may be null.
    /// @return The resolved parser, or nullptr when no kCertManagement-capable provider
    ///         is registered or that provider has no certificate parser.
    [[nodiscard]] provider::cert_management::ICertParser::Sptr ResolveCertParser(
        const provider::ProviderManager::Sptr& provider_manager) const;

    std::weak_ptr<provider::ProviderManager> m_provider_manager;
    std::shared_ptr<ParserCache> m_cache;
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_SLOT_SLOT_HANDLER_FACTORY_HPP

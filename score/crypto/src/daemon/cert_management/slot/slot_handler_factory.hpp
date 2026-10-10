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

#include <atomic>
#include <memory>
#include <mutex>
#include <utility>
#include <variant>

namespace score::crypto::daemon::cert_management
{

/// @brief CertSlotHandlerFactory callable that resolves a slot's storage backend
///        ("DEFAULT" -> FileBackedSlotHandler, otherwise a named provider) on
///        every invocation.
///
/// Owns canonical parser selection for certificate slots. An explicit parser provider
/// name pins the selection; otherwise the kCertManagement capability default is used.
/// Successful resolution is shared across copies of this factory. Failed resolution is
/// not cached, allowing a later call to retry. The provider registry is also consulted
/// for named slot backends.
///
/// The provider manager is held strongly because this callable may resolve parsers and
/// named backends after construction. Copies share the parser cache.
class SlotHandlerFactory final
{
  public:
    /// @brief Construct the factory over a provider registry and optional parser pin.
    /// @param provider_manager Provider registry for parser resolution and named slot
    ///        backends. Held for the lifetime of this factory; may be null when no
    ///        providers are configured.
    /// @param parser_provider_name Exact provider name to use for parsing; empty selects
    ///        the provider manager's kCertManagement default.
    explicit SlotHandlerFactory(provider::ProviderManager::Sptr provider_manager,
                                common::ProviderName parser_provider_name = {})
        : m_provider_manager{std::move(provider_manager)},
          m_parser_provider_name{std::move(parser_provider_name)},
          m_parser_cache{std::make_shared<ParserCache>()}
    {
    }

    /// @brief Resolve and validate the parser before creating slot handlers.
    ///
    /// The parser remains owned by this factory and is supplied to created slot handlers.
    /// Failure is returned without caching, so a later call can retry. Callers may omit
    /// this method and allow operator() to resolve the parser on demand.
    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode> Initialize() const;

    /// @brief Create a slot handler for the given slot configuration.
    /// @param slot Slot configuration; storage_backend selects FileBackedSlotHandler
    ///        ("DEFAULT") or the ICertSlotHandler implementation of a named provider.
    /// @return The constructed handler, or nullptr when the provider registry is absent,
    ///         the named backend provider cannot be found, or the provider declines to
    ///         produce a handler for the slot.
    [[nodiscard]] ICertSlotHandler::Sptr operator()(const CertSlotConfig& slot) const;

  private:
    struct ParserCache
    {
        std::mutex mutex;
        provider::cert_management::ICertParser::Sptr parser;
        // Published after parser assignment so initialized readers can avoid the mutex.
        std::atomic<bool> resolved{false};
    };

    [[nodiscard]] score::crypto::Expected<provider::cert_management::ICertParser::Sptr, common::DaemonErrorCode>
    ResolveCertParser() const;

    provider::ProviderManager::Sptr m_provider_manager;
    common::ProviderName m_parser_provider_name;
    std::shared_ptr<ParserCache> m_parser_cache;
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_SLOT_SLOT_HANDLER_FACTORY_HPP

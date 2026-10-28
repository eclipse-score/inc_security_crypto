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

namespace score::crypto::daemon::cert_management
{

/// @brief Factory that resolves a slot's storage backend
///        ("DEFAULT" -> FileBackedSlotHandler, otherwise a named provider) on
///        every invocation.
///
/// Owns canonical parser selection for certificate slots. An explicit parser provider
/// name pins the selection; otherwise the kCertManagement capability default is used.
/// Successful resolution is cached by the factory. Failed resolution is
/// not cached, allowing a later call to retry. The provider registry is also consulted
/// for named slot backends.
///
/// The provider manager is held strongly because the factory may resolve parsers and
/// named backends after construction.
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
                                common::ProviderName parser_provider_name = {});

    /// @brief Resolve the certificate parser now, so that a failure can be reported at a chosen point.
    ///
    /// Resolution is shared with Create(). A successful result is cached and used for every handler
    /// the factory creates afterwards. A failure is not cached, so the next call tries again. Startup
    /// calls this method when a parser provider is configured, and a failure there stops startup.
    /// Without this call, the parser is resolved on the first call to Create() instead.
    /// @return Success, or the error from the parser resolution.
    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode> Initialize() const;

    /// @brief Create a slot handler for the given slot configuration.
    ///
    /// Resolves the canonical parser before creating the handler. Failed resolution can be retried.
    /// @param slot Slot configuration; storage_backend selects FileBackedSlotHandler
    ///        ("DEFAULT") or the ICertSlotHandler implementation of a named provider.
    /// @return A non-null handler, or the parser or backend selection error.
    [[nodiscard]] score::crypto::Expected<ICertSlotHandler::Sptr, common::DaemonErrorCode> Create(
        const CertSlotConfig& slot) const;

  private:
    struct ParserCache
    {
        std::mutex mutex;
        provider::cert_management::ICertParser::Sptr parser;
        std::atomic<bool> resolved{false};
    };

    [[nodiscard]] score::crypto::Expected<provider::cert_management::ICertParser::Sptr, common::DaemonErrorCode>
    ResolveCertParser() const;

    provider::ProviderManager::Sptr m_provider_manager;
    common::ProviderName m_parser_provider_name;
    mutable ParserCache m_parser_cache;
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_SLOT_SLOT_HANDLER_FACTORY_HPP

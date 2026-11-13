/*******************************************************************************
 *
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
 *******************************************************************************
 */

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CONTEXT_VERIFICATION_CONTEXT_FACTORY_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CONTEXT_VERIFICATION_CONTEXT_FACTORY_HPP

#include "score/crypto/src/daemon/cert_management/core/cert_management_service.hpp"
#include "score/crypto/src/daemon/cert_management/slot/slot_handler_factory.hpp"
#include "score/crypto/src/daemon/common/context/context_creation_request.hpp"
#include "score/crypto/src/daemon/common/context/i_context_factory.hpp"
#include "score/crypto/src/daemon/common/context/i_handler.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/provider/provider_manager.hpp"

#include <memory>

namespace score::crypto::daemon::cert_management
{

/// @brief Creates a CERT:VERIFICATION context handler for each CTX_CREATE of that context type.
///
/// The context is factory-served: the mediator selects no provider for it. Create() resolves the canonical parser
/// through the slot-handler factory. It resolves the path validator from the provider that the request's provider
/// preference selects, and the validator is requested for this context alone. The validator performs the path
/// validation that the context's session requests. The request carries no algorithm for this context type; the decoder
/// refuses one before this factory is called.
///
/// Create() is called from connection threads. It reads the providers through the slot-handler factory and the
/// provider manager, both of which are thread-safe, and builds a new handler, so it is thread-safe.
class CertVerificationContextFactory final : public common::IContextFactory
{
  public:
    /// @brief Construct the factory.
    /// @param parser_source Resolves the canonical parser for each created context. Must be non-null.
    /// @param provider_manager Selects the provider whose path validator each created context uses. Must be non-null.
    /// @param service Certificate management service that each created context operates on. Must be non-null.
    CertVerificationContextFactory(std::shared_ptr<const SlotHandlerFactory> parser_source,
                                   provider::ProviderManager::Sptr provider_manager,
                                   CertManagementService::Sptr service);

    /// @brief Create the handler for a validated CERT:VERIFICATION request.
    /// @param request Validated CTX_CREATE request. Its provider type preference selects the path validator.
    /// @return The new handler. kProviderNotAvailable when no provider satisfies the preference, and
    ///         kUnsupportedOperation when the selected provider supplies no path validator. The parser resolution error
    ///         when no parser is available. Resolution is attempted again on every call until it succeeds.
    [[nodiscard]] score::crypto::Expected<common::Handler::Sptr, common::DaemonErrorCode> Create(
        const common::ContextCreationRequest& request) override;

  private:
    std::shared_ptr<const SlotHandlerFactory> m_parser_source;  ///< Resolves the canonical parser.
    provider::ProviderManager::Sptr m_provider_manager;         ///< Selects the provider for the path validator.
    CertManagementService::Sptr m_service;                      ///< Service that each created context operates on.
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CONTEXT_VERIFICATION_CONTEXT_FACTORY_HPP

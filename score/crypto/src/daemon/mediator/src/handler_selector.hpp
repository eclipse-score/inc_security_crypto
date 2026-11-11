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

#ifndef SCORE_CRYPTO_SRC_DAEMON_MEDIATOR_SRC_HANDLER_SELECTOR_HPP
#define SCORE_CRYPTO_SRC_DAEMON_MEDIATOR_SRC_HANDLER_SELECTOR_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/context/context_creation_request.hpp"
#include "score/crypto/src/daemon/common/context/i_handler.hpp"
#include "score/crypto/src/daemon/common/context/i_mediator_registrar.hpp"
#include "score/crypto/src/daemon/mediator/src/provider_arbiter.hpp"

#include <cstdint>
#include <memory>

namespace score::crypto::daemon::mediator
{

/// @brief Handler chosen for a validated context request.
struct HandlerSelection final
{
    common::Handler::Sptr handler;                  ///< Handler of the new context.
    std::shared_ptr<provider::IProvider> provider;  ///< Provider that created the handler; null for a subsystem-served context.
    bool used_fallback{false};                      ///< True when the fallback provider served the request.
};

/// @brief Chooses the handler for a context request.
///
/// A context type with a registered factory is served by that factory, which creates the handler
/// without a provider. Every other type is served by a provider selected by the provider arbiter.
/// The mediator creates every context through this selection, so the rule exists in one place.
class HandlerSelector final
{
  public:
    /// @brief Construct a selector over the provider arbiter and the subsystem factories.
    /// @param arbiter Selects a provider for context types that no factory serves.
    /// @param context_factories Factories keyed by the context type they serve.
    HandlerSelector(std::shared_ptr<const ProviderArbiter> arbiter,
                    std::shared_ptr<const common::ContextFactoryRegistry> context_factories) noexcept;

    /// @brief Choose the handler for a request.
    /// @param client_id Client that owns the new context; used for key affinity.
    /// @param request Validated context request.
    /// @return The selected handler, or the error to return to the caller. A factory-served type
    ///         that references a key is refused with kKeyOperationNotPermitted before its factory runs.
    [[nodiscard]] score::crypto::Expected<HandlerSelection, score::crypto::CryptoErrorCode> Select(
        std::uint64_t client_id,
        const common::ContextCreationRequest& request) const;

  private:
    std::shared_ptr<const ProviderArbiter> m_arbiter;                           ///< Provider selection.
    std::shared_ptr<const common::ContextFactoryRegistry> m_context_factories;  ///< Subsystem-served types.
};

}  // namespace score::crypto::daemon::mediator

#endif  // SCORE_CRYPTO_SRC_DAEMON_MEDIATOR_SRC_HANDLER_SELECTOR_HPP

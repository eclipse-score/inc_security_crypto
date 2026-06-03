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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_HANDLER_INIT_PARAMS_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_HANDLER_INIT_PARAMS_HPP

#include "score/crypto/daemon/common/types.hpp"
#include "score/crypto/daemon/key_management/interfaces/i_key_handler.hpp"
#include "score/mw/crypto/api/common/types.hpp"
#include <cstdint>
#include <vector>

namespace score::crypto::daemon::provider::handler
{

/// Runtime context supplied by the mediator during single-phase CTX_CREATE.
///
/// Carries the authenticated client identity, the assigned context node ID,
/// provider identity, and an optional bound key handler for keyed contexts
/// (MAC, cipher).  The bound_key_handler pointer is valid for the duration of
/// the InitializeContext() call only.
struct InitializationParams
{
    std::uint64_t client_id{0U};                                 ///< IPC-authenticated client identity
    std::uint64_t context_node_id{0U};                           ///< DataNodeId assigned by the DataManager
    common::ProviderId provider_id{common::kInvalidProviderId};  ///< Numeric provider ID for this context
    std::uint64_t key_node_id{0U};                               ///< Client-supplied key ref node (0 = no key)

    /// Non-owning pointer to the bound key's IKeyHandler.
    /// Handlers downcast to their provider-specific implementation
    /// (e.g. OpenSslKeyHandler, Pkcs11KeyHandler) to access
    /// key material in a type-safe manner.
    /// Set by the mediator after BindKeyToContext(); nullptr when no key is bound.
    const key_management::IKeyHandler* bound_key_handler{nullptr};

    /// Raw CTX_CREATE parameters [0..N] as received on the wire.
    /// Handlers may extract provider-specific extended parameters from this
    /// vector without requiring mediator changes for each new field.
    /// Wire layout: [0]=context_type, [1]=algorithm, [2]=provider_type(opt),
    ///              [3]=key_node_id(opt), [4]=operation_mode(opt, MAC only).
    common::RequestParameters context_creation_params{};
};

}  // namespace score::crypto::daemon::provider::handler

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_HANDLER_INIT_PARAMS_HPP

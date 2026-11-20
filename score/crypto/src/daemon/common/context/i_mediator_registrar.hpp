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

#ifndef SCORE_CRYPTO_SRC_DAEMON_COMMON_CONTEXT_I_MEDIATOR_REGISTRAR_HPP
#define SCORE_CRYPTO_SRC_DAEMON_COMMON_CONTEXT_I_MEDIATOR_REGISTRAR_HPP

#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/daemon/common/context/i_context_factory.hpp"
#include "score/crypto/src/daemon/common/context/i_mediator_query.hpp"
#include "score/crypto/src/daemon/common/context/i_resource_resolver.hpp"
#include "score/crypto/src/daemon/common/context/keyed_registry.hpp"
#include "score/crypto/src/daemon/common/types.hpp"

#include <memory>
#include <string>

namespace score::crypto::daemon::common
{

/// @brief Context factories keyed by context type.
using ContextFactoryRegistry = KeyedRegistry<std::string, IContextFactory>;

/// @brief Resource resolvers keyed by the ResourceType they serve.
using ResourceResolverRegistry = KeyedRegistry<score::crypto::ResourceType, IResourceResolver>;

/// @brief Mediator queries keyed by operation code.
using MediatorQueryRegistry = KeyedRegistry<OperationAction, IMediatorQuery>;

/// @brief The registries a subsystem adds its entries to.
struct MediatorRegistries final
{
    ContextFactoryRegistry& context_factories;     ///< Factories for context types the subsystem serves.
    ResourceResolverRegistry& resource_resolvers;  ///< Resolvers for the resource types the subsystem owns.
    MediatorQueryRegistry& mediator_queries;       ///< Handlers for the mediator operations the subsystem serves.
};

/// @brief A subsystem that adds its entries to the mediator's registries.
///
/// The mediator factory calls `Register` once for each registrar while it builds the registries,
/// before any request is served. A subsystem registers all of its entries in that one call.
class IMediatorRegistrar
{
  public:
    /// @brief Shared pointer to a registrar.
    using Sptr = std::shared_ptr<IMediatorRegistrar>;

    /// @brief Virtual destructor.
    virtual ~IMediatorRegistrar() = default;

    /// @brief Add the subsystem's entries to the registries.
    /// @param registries Registries to add to.
    /// @return True if every entry was registered. False if the registries rejected an entry, in
    ///         which case the mediator is not created.
    [[nodiscard]] virtual bool Register(MediatorRegistries& registries) const = 0;
};

}  // namespace score::crypto::daemon::common

#endif  // SCORE_CRYPTO_SRC_DAEMON_COMMON_CONTEXT_I_MEDIATOR_REGISTRAR_HPP

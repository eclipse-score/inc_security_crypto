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

#include "score/crypto/src/daemon/mediator/mediator_factory.hpp"

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/data_plane/src/shm_registry.hpp"
#include "score/crypto/src/daemon/mediator/mediator_impl.hpp"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"
#include "score/crypto/src/daemon/mediator/src/context_assembler.hpp"
#include "score/crypto/src/daemon/mediator/src/provider_arbiter.hpp"

#include "score/mw/log/logging.h"

#include <memory>
#include <utility>
#include <vector>

namespace score::crypto::daemon::mediator
{

score::crypto::Expected<std::shared_ptr<IMediator>, common::DaemonErrorCode> MediatorFactory::Create(
    data_manager::IDataManager::Sptr data_manager,
    provider::ProviderManager::Sptr provider_manager,
    key_management::KeyManagementService::Sptr km_service,
    const std::vector<common::IMediatorRegistrar::Sptr>& registrars)
{
    auto context_factories = std::make_shared<ContextFactoryRegistry>();
    auto resource_resolvers = std::make_shared<ResourceResolverRegistry>();
    auto mediator_queries = std::make_shared<MediatorQueryRegistry>();

    common::MediatorRegistries registries{*context_factories, *resource_resolvers, *mediator_queries};
    for (const auto& registrar : registrars)
    {
        if (!registrar || !registrar->Register(registries))
        {
            score::mw::log::LogError() << "A subsystem registration for the mediator was rejected";
            return score::crypto::make_unexpected(common::DaemonErrorCode::kInternalError);
        }
    }

    // The mediator handles these operations itself and never offers them to a query.
    for (const auto action : operations::kBuiltInActions)
    {
        if (mediator_queries->Find(action))
        {
            score::mw::log::LogError() << "A mediator query is registered for built-in operation " << action;
            return score::crypto::make_unexpected(common::DaemonErrorCode::kInvalidArgument);
        }
    }

    MediatorDependencies deps;
    deps.arbiter = std::make_shared<ProviderArbiter>(provider_manager, km_service);
    deps.assembler = std::make_shared<ContextAssembler>(data_manager, km_service);
    deps.data_manager = std::move(data_manager);
    deps.provider_manager = std::move(provider_manager);
    // The shared-memory registry is shared by every connection so that ShmDataNodes can release
    // quota regardless of which thread destroys them.
    deps.shm_registry = std::make_shared<data_plane::ShmRegistry>();
    deps.context_factories = std::move(context_factories);
    deps.resource_resolvers = std::move(resource_resolvers);
    deps.mediator_queries = std::move(mediator_queries);

    std::shared_ptr<IMediator> mediator = std::make_shared<MediatorImpl>(std::move(deps));
    return mediator;
}

}  // namespace score::crypto::daemon::mediator

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

#include "score/crypto/daemon/key_management/key_management_module.hpp"

#include "score/crypto/daemon/key_management/slot/config_driven_slot_catalog.hpp"
#include "score/crypto/daemon/provider/i_provider.hpp"

#include "score/mw/log/logging.h"

#include <memory>

namespace score::crypto::daemon::key_management
{

namespace
{

}  // namespace

KeyManagementModule::Sptr KeyManagementModule::Create(data_manager::IDataManager::Sptr data_manager,
                                                      provider::ProviderManager::Sptr provider_manager,
                                                      const config::KeyConfig& key_config)
{
    auto module = Sptr(new KeyManagementModule());

    module->m_provider_manager = provider_manager;
    module->m_slot_registry = std::make_shared<SlotRegistry>();

    // Load slot definitions from parsed configuration.
    ConfigDrivenSlotCatalog catalog{key_config};
    catalog.Load(*module->m_slot_registry);

    // Create the core key management service with all dependencies.
    module->m_service =
        std::make_shared<KeyManagementService>(std::move(data_manager), provider_manager, module->m_slot_registry);

    // Inject the service into every registered provider so that factory-created
    // handlers can use it without mediator-level injection.
    provider_manager->ForEachProvider([&](const auto& /*id*/, const auto& provider) {
        provider->SetKeyManagementService(module->m_service);
    });

    // Resolve provider names → numeric IDs in all slots.
    // This must happen after providers are registered and SetKeyManagementService is called.
    module->m_slot_registry->ResolveProviderIds(*provider_manager);

    score::mw::log::LogDebug() << LOG_PREFIX << "Key management module initialized from config. Slots: "
                               << module->m_slot_registry->GetSlotCount();

    return module;
}

SlotRegistry::Sptr KeyManagementModule::GetSlotRegistry() const
{
    return m_slot_registry;
}

KeyManagementService::Sptr KeyManagementModule::GetService() const
{
    return m_service;
}

provider::ProviderManager::Sptr KeyManagementModule::GetProviderManager() const
{
    return m_provider_manager;
}

}  // namespace score::crypto::daemon::key_management

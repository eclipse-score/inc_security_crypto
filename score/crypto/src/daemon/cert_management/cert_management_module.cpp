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
#include "score/crypto/src/daemon/cert_management/cert_management_module.hpp"

#include "score/crypto/src/daemon/cert_management/slot/cert_slot_manager.hpp"
#include "score/crypto/src/daemon/cert_management/slot/config_driven_slot_catalog.hpp"
#include "score/crypto/src/daemon/cert_management/slot/slot_handler_factory.hpp"
#include "score/crypto/src/daemon/cert_management/truststore/config_driven_trust_store_catalog.hpp"

namespace score::crypto::daemon::cert_management
{
CertManagementModule::Sptr CertManagementModule::Create(data_manager::IDataManager::Sptr data_manager,
                                                        provider::ProviderManager::Sptr provider_manager,
                                                        const config::CertificateConfig& config)
{
    auto module = Sptr(new CertManagementModule());
    auto slot_registry = std::make_shared<CertSlotRegistry>();
    ConfigDrivenSlotCatalog catalog{config};
    catalog.Load(*slot_registry);
    auto trust_store_manager = std::make_shared<TrustStoreManager>();
    ConfigDrivenTrustStoreCatalog trust_catalog{config};

    // SlotHandlerFactory holds ProviderManager only weakly: CertSlotManager outlives
    // this Create() call and is reachable from a provider (e.g.
    // OpenSSL::m_certManagementService), so a strong reference here would form a
    // cycle back to ProviderManager. provider_manager is only needed for this
    // call, so it is passed as a local parameter rather than a CertManagementModule
    // member.
    auto slot_manager = std::make_shared<CertSlotManager>(slot_registry, SlotHandlerFactory{provider_manager});

    trust_catalog.Load(*trust_store_manager, slot_registry, slot_manager);
    module->m_service = std::make_shared<CertManagementService>(
        std::move(data_manager), slot_registry, trust_store_manager, slot_manager);
    if (provider_manager)
    {
        provider_manager->ForEachProvider([&](const auto& /*id*/, const auto& provider) {
            provider->SetCertManagementService(module->m_service);
        });
    }
    return module;
}
}  // namespace score::crypto::daemon::cert_management

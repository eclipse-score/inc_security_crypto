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

#include "score/crypto/src/daemon/cert_management/slot/config_driven_slot_catalog.hpp"
#include "score/crypto/src/daemon/cert_management/slot/file_backed_slot_handler.hpp"
#include "score/crypto/src/daemon/cert_management/truststore/config_driven_trust_store_catalog.hpp"
#include "score/mw/log/logging.h"

namespace score::crypto::daemon::cert_management
{
CertManagementModule::Sptr CertManagementModule::Create(data_manager::IDataManager::Sptr data_manager,
                                                        provider::ProviderManager::Sptr provider_manager,
                                                        const config::CertificateConfig& config)
{
    auto module = Sptr(new CertManagementModule());
    module->m_provider_manager = std::move(provider_manager);
    module->m_slots = std::make_shared<CertSlotRegistry>();
    ConfigDrivenSlotCatalog catalog{config};
    catalog.Load(*module->m_slots);
    module->m_trust_stores = std::make_shared<TrustStoreManager>();
    ConfigDrivenTrustStoreCatalog trust_catalog{config};
    // Resolve the cert parser once at startup; injected into every FileBackedSlotHandler.
    // Contract: a provider that advertises kCertManagement must implement GetCertParser().
    // Failure to do so is a misconfiguration — log it loudly so it is visible at startup
    // rather than silently postponed until the first slot load attempt.
    provider::cert_management::ICertParser::Sptr cert_parser;
    if (module->m_provider_manager)
    {
        auto cert_prov =
            module->m_provider_manager->GetProviderForCapability(common::ProviderCapability::kCertManagement);
        if (cert_prov)
        {
            cert_parser = cert_prov->GetCertParser();
            if (!cert_parser)
                score::mw::log::LogError() << "[CertMgmt] Provider '" << cert_prov->GetProviderName()
                                           << "' advertises kCertManagement but GetCertParser() returned null."
                                           << " Providers claiming kCertManagement must implement GetCertParser()."
                                           << " File-backed slot loads will fail until this is resolved.";
        }
        else
        {
            score::mw::log::LogWarn() << "[CertMgmt] No provider with kCertManagement capability registered."
                                      << " File-backed certificate slot loads will fail.";
        }
    }

    CertSlotHandlerFactory slot_handler_factory = [provider_manager = module->m_provider_manager,
                                                   cert_parser](const CertSlotConfig& slot) -> ICertSlotHandler::Sptr {
        if (slot.storage_backend == "DEFAULT")
            return std::make_shared<FileBackedSlotHandler>(cert_parser);

        if (!provider_manager)
            return nullptr;

        auto provider = provider_manager->GetProvider(slot.storage_backend);
        if (!provider)
            return nullptr;
        return provider->GetCertSlotHandler(slot, cert_parser);
    };
    trust_catalog.Load(*module->m_trust_stores, module->m_slots, slot_handler_factory);
    module->m_service = std::make_shared<CertManagementService>(
        std::move(data_manager), module->m_slots, module->m_trust_stores, std::move(slot_handler_factory));
    if (module->m_provider_manager)
    {
        module->m_provider_manager->ForEachProvider([&](const auto& /*id*/, const auto& provider) {
            provider->SetCertManagementService(module->m_service);
        });
    }
    return module;
}
}  // namespace score::crypto::daemon::cert_management

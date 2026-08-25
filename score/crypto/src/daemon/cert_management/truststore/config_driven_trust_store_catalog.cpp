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

#include "score/crypto/src/daemon/cert_management/truststore/config_driven_trust_store_catalog.hpp"

#include "score/mw/log/logging.h"

namespace score::crypto::daemon::cert_management
{

ConfigDrivenTrustStoreCatalog::ConfigDrivenTrustStoreCatalog(const config::CertificateConfig& config) : m_config{config}
{
}

void ConfigDrivenTrustStoreCatalog::Load(TrustStoreManager& manager,
                                         CertSlotRegistry::Sptr registry,
                                         CertSlotHandlerFactory slot_handler_factory)
{
    const auto& entries = m_config.GetTrustStoreEntries();

    std::vector<TrustStoreConfig> configs;
    configs.reserve(entries.size());

    for (const auto& src : entries)
    {
        TrustStoreConfig cfg;
        cfg.store_name = src.store_name;
        cfg.conditional_slot_initialization =
            static_cast<ConditionalSlotInitialization>(src.conditional_slot_initialization);
        for (const auto& src_member : src.members)
        {
            TrustStoreMemberConfig member;
            member.slot_name = src_member.slot_name;
            member.kind = static_cast<TrustStoreMemberKind>(src_member.kind);
            cfg.members.push_back(std::move(member));
        }
        cfg.access_policy = {src.allowed_uids, src.allowed_write_uids};
        cfg.deployment_path = src.deployment_path;
        cfg.deployment_format = src.deployment_format;
        configs.push_back(std::move(cfg));

        score::mw::log::LogDebug() << kLogPrefix << "Registered trust store '" << src.store_name << "' ("
                                   << src.members.size() << " member slot(s))";
    }

    score::mw::log::LogDebug() << kLogPrefix << "Loading " << configs.size() << " trust store(s) from configuration.";
    manager.Load(std::move(configs), std::move(registry), std::move(slot_handler_factory));
    for (const auto& mapping : m_config.GetAppTrustStoreEntries())
        manager.RegisterAppResource(mapping.uid, mapping.app_resource_id, mapping.trust_store_name);
}

}  // namespace score::crypto::daemon::cert_management

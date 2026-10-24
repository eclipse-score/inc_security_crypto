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

#include "score/crypto/src/daemon/cert_management/slot/config_driven_slot_catalog.hpp"

#include "score/crypto/src/daemon/cert_management/interfaces/cert_slot_config.hpp"
#include "score/crypto/src/daemon/cert_management/slot/slot_registry.hpp"

#include "score/mw/log/logging.h"

namespace score::crypto::daemon::cert_management
{

ConfigDrivenSlotCatalog::ConfigDrivenSlotCatalog(const config::CertificateConfig& cert_config)
    : m_cert_config{cert_config}
{
}

void ConfigDrivenSlotCatalog::Load(CertSlotRegistry& registry)
{
    const auto& entries = m_cert_config.GetSlotEntries();

    for (const auto& entry : entries)
    {
        CertSlotConfig config{};
        config.slot_name = entry.slot_name;
        config.storage_backend = entry.storage_backend;
        config.access_policy.allowed_uids = entry.allowed_uids;
        config.access_policy.allowed_write_uids = entry.allowed_write_uids;
        config.deployment_path = entry.deployment_path;
        config.deployment_format = entry.deployment_format;
        switch (entry.integrity_policy)
        {
            case config::CertificateConfig::IntegrityPolicy::kDisabled:
                config.integrity_policy = IntegrityPolicy::kDisabled;
                break;
            case config::CertificateConfig::IntegrityPolicy::kRequired:
                config.integrity_policy = IntegrityPolicy::kRequired;
                break;
        }

        registry.RegisterSlot(std::move(config));

        const std::string integrity_name =
            entry.integrity_policy == config::CertificateConfig::IntegrityPolicy::kRequired ? "required" : "disabled";
        score::mw::log::LogDebug() << kLogPrefix << "Registered cert slot '" << entry.slot_name
                                   << "' (storage_backend=" << entry.storage_backend
                                   << ", integrity_policy=" << integrity_name << ")";
    }

    score::mw::log::LogDebug() << kLogPrefix << "Loaded " << entries.size() << " cert slot(s) from configuration.";

    // Register per-application resource ID mappings.
    for (const auto& mapping : m_cert_config.GetAppCertSlotMappings())
    {
        registry.RegisterAppResource(mapping.uid, mapping.app_resource_id, mapping.slot_name);
    }
}

}  // namespace score::crypto::daemon::cert_management

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
#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CERT_MANAGEMENT_MODULE_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CERT_MANAGEMENT_MODULE_HPP

#include "score/crypto/src/daemon/cert_management/core/cert_management_service.hpp"
#include "score/crypto/src/daemon/cert_management/slot/slot_registry.hpp"
#include "score/crypto/src/daemon/config/inc/config.hpp"
#include "score/crypto/src/daemon/provider/provider_manager.hpp"

namespace score::crypto::daemon::cert_management
{
class CertManagementModule final
{
  public:
    using Sptr = std::shared_ptr<CertManagementModule>;
    static Sptr Create(data_manager::IDataManager::Sptr,
                       provider::ProviderManager::Sptr,
                       const config::CertificateConfig&);
    CertSlotRegistry::Sptr GetSlotRegistry() const
    {
        return m_slots;
    }
    CertManagementService::Sptr GetService() const
    {
        return m_service;
    }
    provider::ProviderManager::Sptr GetProviderManager() const
    {
        return m_provider_manager;
    }

  private:
    CertManagementModule() = default;
    CertSlotRegistry::Sptr m_slots;
    TrustStoreManager::Sptr m_trust_stores;
    CertManagementService::Sptr m_service;
    provider::ProviderManager::Sptr m_provider_manager;
};
}  // namespace score::crypto::daemon::cert_management
#endif

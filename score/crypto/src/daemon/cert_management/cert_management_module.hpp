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
#include "score/crypto/src/daemon/config/inc/config.hpp"
#include "score/crypto/src/daemon/provider/provider_manager.hpp"

namespace score::crypto::daemon::cert_management
{
class CertManagementModule final
{
  public:
    using Sptr = std::shared_ptr<CertManagementModule>;

    /// @brief Build the certificate-management subsystem and wire it to the given providers.
    /// @param data_manager Daemon data manager used for client-tree DataNode registration.
    /// @param provider_manager Provider registry consulted to resolve certificate parsers
    ///        and provider-backed slot handlers; may be null if no providers are registered.
    /// @param config Certificate slot, trust store, and parser-provider configuration.
    /// @return A fully constructed module, or nullptr when an explicitly configured parser
    ///         provider is unavailable or does not provide the required parser capability.
    static Sptr Create(data_manager::IDataManager::Sptr data_manager,
                       provider::ProviderManager::Sptr provider_manager,
                       const config::CertificateConfig& config);

    /// @brief Return the certificate-management service owned by this module.
    CertManagementService::Sptr GetService() const
    {
        return m_service;
    }

  private:
    CertManagementModule() = default;
    CertManagementService::Sptr m_service;
};
}  // namespace score::crypto::daemon::cert_management
#endif

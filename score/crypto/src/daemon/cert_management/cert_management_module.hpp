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
#include "score/crypto/src/daemon/common/context/i_mediator_registrar.hpp"
#include "score/crypto/src/daemon/config/inc/config.hpp"
#include "score/crypto/src/daemon/provider/provider_manager.hpp"

#include <memory>

namespace score::crypto::daemon::cert_management
{

class SlotHandlerFactory;

/// @brief Certificate-management subsystem. Registers its context factory, mediator queries, and
///        resource resolver with the mediator at startup.
class CertManagementModule final : public common::IMediatorRegistrar
{
  public:
    using Sptr = std::shared_ptr<CertManagementModule>;

    /// @brief Build the certificate-management subsystem and wire it to the given providers.
    /// @param data_manager Daemon data manager used for client-tree DataNode registration.
    /// @param provider_manager Provider registry consulted to resolve certificate parsers
    ///        and provider-backed slot handlers; may be null if no providers are registered.
    /// @param config Certificate slot, trust store, and parser-provider configuration.
    /// @return A fully constructed module, or nullptr when the named parser provider cannot be resolved or the
    ///         trust-store configuration fails to load. Without a named parser provider the module is always
    ///         returned; the parser is resolved on first use, and CERT:MANAGEMENT contexts fail to create while
    ///         no parser is available.
    static Sptr Create(data_manager::IDataManager::Sptr data_manager,
                       provider::ProviderManager::Sptr provider_manager,
                       const config::CertificateConfig& config);

    /// @brief Return the certificate-management service owned by this module.
    CertManagementService::Sptr GetService() const
    {
        return m_service;
    }

    /// @brief Register the CERT:MANAGEMENT and CERT:TRUST_STORE context factories, the certificate and trust-store
    ///        object and member queries, and the certificate-slot and trust-store resource resolvers with the mediator
    ///        registries.
    /// @param registries Registries to add to.
    /// @return True if every entry was registered. False if the registries rejected an entry.
    [[nodiscard]] bool Register(common::MediatorRegistries& registries) const override;

  private:
    CertManagementModule() = default;

    CertManagementService::Sptr m_service;
    /// Resolves the canonical parser; shared with the slot manager and with every CERT:MANAGEMENT context.
    std::shared_ptr<const SlotHandlerFactory> m_parser_source;
};
}  // namespace score::crypto::daemon::cert_management
#endif

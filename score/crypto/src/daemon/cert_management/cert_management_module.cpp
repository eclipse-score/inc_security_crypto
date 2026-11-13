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

#include "score/crypto/src/daemon/cert_management/context/management/context_factory.hpp"
#include "score/crypto/src/daemon/cert_management/context/trust_store/context_factory.hpp"
#include "score/crypto/src/daemon/cert_management/context/verification/context_factory.hpp"
#include "score/crypto/src/daemon/cert_management/query/get_cert_slot_object_query.hpp"
#include "score/crypto/src/daemon/cert_management/query/get_certificate_object_query.hpp"
#include "score/crypto/src/daemon/cert_management/query/get_certificate_public_key_query.hpp"
#include "score/crypto/src/daemon/cert_management/query/get_trust_store_member_id_list_query.hpp"
#include "score/crypto/src/daemon/cert_management/query/get_trust_store_member_object_query.hpp"
#include "score/crypto/src/daemon/cert_management/resolver/cert_slot_resource_resolver.hpp"
#include "score/crypto/src/daemon/cert_management/resolver/trust_store_resource_resolver.hpp"
#include "score/crypto/src/daemon/cert_management/slot/cert_slot_manager.hpp"
#include "score/crypto/src/daemon/cert_management/slot/config_driven_slot_catalog.hpp"
#include "score/crypto/src/daemon/cert_management/slot/slot_handler_factory.hpp"
#include "score/crypto/src/daemon/cert_management/truststore/config_driven_trust_store_catalog.hpp"
#include "score/crypto/src/daemon/common/context/context_types.hpp"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"
#include "score/mw/log/logging.h"

#include <string>
#include <utility>

namespace score::crypto::daemon::cert_management
{

CertManagementModule::Sptr CertManagementModule::Create(data_manager::IDataManager::Sptr data_manager,
                                                        provider::ProviderManager::Sptr provider_manager,
                                                        const config::CertificateConfig& config)
{
    // A named parser provider must resolve during startup. Without a name, the parser is resolved on first use, so a
    // provider that is not yet available at startup can serve certificate operations once it is ready.
    auto slot_handler_factory = std::make_shared<SlotHandlerFactory>(provider_manager, config.GetParserProviderName());
    if (!config.GetParserProviderName().empty())
    {
        const auto parser_initialization = slot_handler_factory->Initialize();
        if (!parser_initialization.has_value())
        {
            score::mw::log::LogError()
                << "CertManagementModule: the named certificate parser provider could not be resolved";
            return nullptr;
        }
    }

    auto module = Sptr(new CertManagementModule());
    auto slot_registry = std::make_shared<CertSlotRegistry>();
    ConfigDrivenSlotCatalog catalog{config};
    catalog.Load(*slot_registry);
    auto trust_store_manager = std::make_shared<TrustStoreManager>();
    ConfigDrivenTrustStoreCatalog trust_catalog{config};

    // The slot manager and the module share one slot-handler factory, so every consumer resolves the parser through
    // the same cache.
    auto slot_manager = std::make_shared<CertSlotManager>(slot_registry, slot_handler_factory);

    if (!trust_catalog.Load(*trust_store_manager, slot_registry, slot_manager).has_value())
    {
        return nullptr;
    }
    module->m_service = std::make_shared<CertManagementService>(
        std::move(data_manager), slot_registry, trust_store_manager, slot_manager);
    module->m_parser_source = std::move(slot_handler_factory);
    module->m_provider_manager = std::move(provider_manager);
    return module;
}

bool CertManagementModule::Register(common::MediatorRegistries& registries) const
{
    const std::string context_type{common::context_types::kCertManagement};
    if (!registries.context_factories.Register(
            context_type, std::make_shared<CertManagementContextFactory>(m_parser_source, m_service)))
    {
        return false;
    }

    const std::string trust_store_context_type{common::context_types::kCertTrustStore};
    if (!registries.context_factories.Register(
            trust_store_context_type, std::make_shared<TrustStoreManagementContextFactory>(m_parser_source, m_service)))
    {
        return false;
    }

    const std::string verification_context_type{common::context_types::kCertVerification};
    if (!registries.context_factories.Register(
            verification_context_type,
            std::make_shared<CertVerificationContextFactory>(m_parser_source, m_provider_manager, m_service)))
    {
        return false;
    }

    if (!registries.mediator_queries.Register(mediator::operations::GET_CERTIFICATE_OBJECT,
                                              std::make_shared<query::GetCertificateObjectQuery>(m_service)))
    {
        return false;
    }
    if (!registries.mediator_queries.Register(mediator::operations::GET_CERT_SLOT_OBJECT,
                                              std::make_shared<query::GetCertSlotObjectQuery>(m_service)))
    {
        return false;
    }
    if (!registries.mediator_queries.Register(mediator::operations::GET_CERTIFICATE_PUBLIC_KEY,
                                              std::make_shared<query::GetCertificatePublicKeyQuery>(m_service)))
    {
        return false;
    }
    if (!registries.mediator_queries.Register(mediator::operations::GET_TRUST_STORE_MEMBER_ID_LIST,
                                              std::make_shared<query::GetTrustStoreMemberIdListQuery>(m_service)))
    {
        return false;
    }
    if (!registries.mediator_queries.Register(mediator::operations::GET_TRUST_STORE_MEMBER_OBJECT,
                                              std::make_shared<query::GetTrustStoreMemberObjectQuery>(m_service)))
    {
        return false;
    }

    if (!registries.resource_resolvers.Register(score::crypto::ResourceType::kCertSlot,
                                                std::make_shared<CertSlotResourceResolver>(m_service)))
    {
        return false;
    }
    return registries.resource_resolvers.Register(score::crypto::ResourceType::kCertificateTrustStore,
                                                  std::make_shared<TrustStoreResourceResolver>(m_service));
}

}  // namespace score::crypto::daemon::cert_management

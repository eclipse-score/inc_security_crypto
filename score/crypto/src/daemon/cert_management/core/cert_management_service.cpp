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
#include "score/crypto/src/daemon/cert_management/core/cert_management_service.hpp"
#include "score/crypto/src/daemon/cert_management/nodes/cert_slot_data_node.hpp"
#include "score/crypto/src/daemon/cert_management/nodes/trust_store_data_node.hpp"
#include "score/crypto/src/daemon/data_manager/data_node_accessor.hpp"

namespace score::crypto::daemon::cert_management
{
using Error = common::DaemonErrorCode;

CertManagementService::CertManagementService(data_manager::IDataManager::Sptr data_manager,
                                             CertSlotRegistry::Sptr slot_registry,
                                             TrustStoreManager::Sptr trust_store_manager,
                                             CertSlotHandlerFactory slot_handler_factory)
    : m_data_manager{std::move(data_manager)},
      m_slot_registry{std::move(slot_registry)},
      m_trust_stores{std::move(trust_store_manager)},
      m_slot_handler_factory{std::move(slot_handler_factory)}
{
}

score::crypto::Expected<CertDataNodeResult, Error> CertManagementService::RegisterCertMaterial(
    const CertRegistrationParams& params,
    CertObject::Sptr object)
{
    if (!object || !m_data_manager)
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    auto entry = std::make_shared<CertEntry>(std::move(object), params.slot_handle);
    auto id = params.slot_handle.IsValid() ? m_cert_registry.RegisterSlotCert(params.slot_handle, entry)
                                           : m_cert_registry.RegisterEphemeralCert(entry);
    if (id == 0U)
    {
        id = m_cert_registry.FindSlotRegistryId(params.slot_handle);
        entry = m_cert_registry.FindById(id);
        if (!entry)
            return score::crypto::make_unexpected(Error::kInternalError);
    }
    auto captured = entry;
    auto node = std::make_shared<CertDataNode>(entry, id, params.client_id, [this](CertRegistryId rid) {
        m_cert_registry.Unregister(rid);
    });
    auto node_id = m_data_manager->addChildNode(params.client_id, params.parent_id, node);
    if (!node_id)
        return score::crypto::make_unexpected(Error::kInternalError);
    return CertDataNodeResult{*node_id, std::move(captured)};
}

score::crypto::Expected<CertDataNodeResult, Error> CertManagementService::LoadOrShare(
    const CertRegistrationParams& params,
    ICertSlotHandler& handler,
    const CertSlotConfig& config)
{
    auto existing = m_cert_registry.FindBySlot(params.slot_handle);
    if (existing)
    {
        const auto id = m_cert_registry.FindSlotRegistryId(params.slot_handle);
        auto node = std::make_shared<CertDataNode>(existing, id, params.client_id, [this](CertRegistryId rid) {
            m_cert_registry.Unregister(rid);
        });
        auto node_id = m_data_manager->addChildNode(params.client_id, params.parent_id, node);
        if (!node_id)
            return score::crypto::make_unexpected(Error::kInternalError);
        return CertDataNodeResult{*node_id, std::move(existing)};
    }
    auto loaded = handler.LoadCertificate(config);
    if (!loaded)
        return score::crypto::make_unexpected(loaded.error());
    return RegisterCertMaterial(params, std::move(*loaded));
}

score::crypto::Expected<std::monostate, Error> CertManagementService::ReleaseCert(data_manager::ClientId client_id,
                                                                                  data_manager::DataNodeId node_id)
{
    if (!m_data_manager->deleteNode(client_id, node_id))
        return score::crypto::make_unexpected(Error::kInvalidResourceId);
    return std::monostate{};
}

void CertManagementService::CleanupClient(data_manager::ClientId client_id)
{
    m_cert_registry.CleanupClient(client_id);
    m_cert_slot_node_cache.erase(client_id);
    m_trust_store_node_cache.erase(client_id);
    if (m_trust_stores)
        m_trust_stores->CleanupClient(client_id);
}

// ---------------------------------------------------------------------------
// Resource resolution — mediator resource resolvers
// ---------------------------------------------------------------------------

score::crypto::Expected<data_manager::DataNodeId, Error> CertManagementService::ResolveCertSlot(
    const std::string& resource_name,
    data_manager::ClientId client_id)
{
    if (!m_data_manager || !m_slot_registry)
        return score::crypto::make_unexpected(Error::kInternalError);

    // Dedup: same client resolving the same slot twice returns the cached node id.
    auto& client_cache = m_cert_slot_node_cache[client_id];
    const auto it = client_cache.find(resource_name);
    if (it != client_cache.end())
        return it->second;

    auto handle_res = m_slot_registry->ResolveAppResource(resource_name, client_id);
    if (!handle_res.has_value())
        return score::crypto::make_unexpected(handle_res.error());

    auto node = std::make_shared<CertSlotDataNode>(handle_res.value(), m_slot_registry);
    auto node_id = m_data_manager->addNode(client_id, std::move(node));
    if (!node_id.has_value())
        return score::crypto::make_unexpected(Error::kInternalError);

    client_cache[resource_name] = node_id.value();
    return node_id.value();
}

score::crypto::Expected<data_manager::DataNodeId, Error> CertManagementService::ResolveTrustStore(
    const std::string& resource_name,
    data_manager::ClientId client_id)
{
    if (!m_data_manager || !m_trust_stores)
        return score::crypto::make_unexpected(Error::kInternalError);

    // Dedup: same client resolving the same trust store twice returns the cached node id.
    auto& client_cache = m_trust_store_node_cache[client_id];
    const auto it = client_cache.find(resource_name);
    if (it != client_cache.end())
        return it->second;

    auto handle_res = m_trust_stores->ResolveAppResource(resource_name, client_id);
    if (!handle_res.has_value())
        return score::crypto::make_unexpected(handle_res.error());

    auto node = std::make_shared<TrustStoreDataNode>(handle_res.value(), m_trust_stores);
    auto node_id = m_data_manager->addNode(client_id, std::move(node));
    if (!node_id.has_value())
        return score::crypto::make_unexpected(Error::kInternalError);

    client_cache[resource_name] = node_id.value();
    return node_id.value();
}

// ---------------------------------------------------------------------------
// Operation helpers — executor call sites
// ---------------------------------------------------------------------------

score::crypto::Expected<ResolvedCertSlot, Error> CertManagementService::ResolveSlotForOperation(
    data_manager::ClientId client_id,
    data_manager::DataNodeId slot_node_id)
{
    if (!m_data_manager)
        return score::crypto::make_unexpected(Error::kInternalError);

    auto acc_res = m_data_manager->getNodeAccessor(client_id, slot_node_id);
    if (!acc_res.has_value())
        return score::crypto::make_unexpected(Error::kInvalidArgument);

    auto typed_res = std::move(acc_res).value().downCast<CertSlotDataNode>();
    if (!typed_res.has_value())
        return score::crypto::make_unexpected(Error::kInvalidArgument);

    auto& slot_node = *typed_res.value();
    const auto handle = slot_node.GetSlotHandle();
    auto config_res = m_slot_registry->GetConfig(handle);
    if (!config_res.has_value())
        return score::crypto::make_unexpected(config_res.error());

    if (!m_slot_handler_factory)
        return score::crypto::make_unexpected(Error::kInternalError);
    auto handler = m_slot_handler_factory(*config_res.value());
    if (!handler)
        return score::crypto::make_unexpected(Error::kInternalError);

    return ResolvedCertSlot{handle, config_res.value(), std::move(handler)};
}

score::crypto::Expected<CertObject::Sptr, Error> CertManagementService::ResolveCertForOperation(
    data_manager::ClientId client_id,
    data_manager::DataNodeId cert_node_id)
{
    if (!m_data_manager)
        return score::crypto::make_unexpected(Error::kInternalError);

    auto acc_res = m_data_manager->getNodeAccessor(client_id, cert_node_id);
    if (!acc_res.has_value())
        return score::crypto::make_unexpected(Error::kInvalidArgument);

    auto typed_res = std::move(acc_res).value().downCast<CertDataNode>();
    if (!typed_res.has_value())
        return score::crypto::make_unexpected(Error::kInvalidArgument);

    auto entry = typed_res.value()->GetCertEntry();
    if (!entry)
        return score::crypto::make_unexpected(Error::kInternalError);
    return entry->GetCertObject();
}

score::crypto::Expected<TrustStoreHandle, Error> CertManagementService::ResolveTrustStoreForOperation(
    data_manager::ClientId client_id,
    data_manager::DataNodeId ts_node_id)
{
    if (!m_data_manager)
        return score::crypto::make_unexpected(Error::kInternalError);

    auto acc_res = m_data_manager->getNodeAccessor(client_id, ts_node_id);
    if (!acc_res.has_value())
        return score::crypto::make_unexpected(Error::kInvalidArgument);

    auto typed_res = std::move(acc_res).value().downCast<TrustStoreDataNode>();
    if (!typed_res.has_value())
        return score::crypto::make_unexpected(Error::kInvalidArgument);

    return typed_res.value()->GetTrustStoreHandle();
}

void CertManagementService::NotifySlotCertChanged(CertSlotHandle slot_handle)
{
    if (!m_trust_stores)
        return;
    const auto memberships = m_trust_stores->GetMembershipsForSlot(slot_handle);
    for (const auto ts_id : memberships)
        m_trust_stores->NotifySlotChanged(ts_id, slot_handle);
}

}  // namespace score::crypto::daemon::cert_management

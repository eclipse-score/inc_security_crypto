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
#include "score/crypto/src/daemon/cert_management/nodes/cert_data_node.hpp"
#include "score/crypto/src/daemon/cert_management/nodes/cert_slot_data_node.hpp"
#include "score/crypto/src/daemon/cert_management/nodes/trust_store_data_node.hpp"
#include "score/crypto/src/daemon/data_manager/data_node_accessor.hpp"

namespace score::crypto::daemon::cert_management
{
using Error = common::DaemonErrorCode;

CertManagementService::CertManagementService(data_manager::IDataManager::Sptr data_manager,
                                             CertSlotRegistry::Sptr slot_registry,
                                             TrustStoreManager::Sptr trust_store_manager,
                                             CertSlotManager::Sptr slot_manager)
    : m_slot_registry{std::move(slot_registry)},
      m_slot_manager{std::move(slot_manager)},
      m_trust_store_manager{std::move(trust_store_manager)},
      m_data_manager{std::move(data_manager)}
{
}

score::crypto::Expected<CertDataNodeResult, Error> CertManagementService::RegisterCertMaterial(
    const CertRegistrationParams& params,
    CertObject::Sptr object)
{
    if (!object || !m_data_manager)
    {
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }
    auto instance = std::make_shared<CertEntry>(params.client_id, std::move(object), params.slot_handle);
    auto id = params.slot_handle.IsValid() ? m_cert_registry->RegisterSlotCert(params.slot_handle, instance)
                                           : m_cert_registry->RegisterEphemeralCert(instance);
    if (id == 0U)
    {
        return score::crypto::make_unexpected(Error::kInternalError);
    }
    auto node = std::make_shared<CertDataNode>(instance, m_cert_registry, id, params.client_id);
    auto node_id = m_data_manager->addChildNode(params.client_id, params.parent_id, node);
    if (!node_id.has_value())
    {
        return score::crypto::make_unexpected(Error::kInternalError);
    }
    return CertDataNodeResult{node_id.value(), std::move(instance)};
}

score::crypto::Expected<CertDataNodeResult, Error> CertManagementService::Load(const CertRegistrationParams& params)
{
    if (!m_slot_manager)
    {
        return score::crypto::make_unexpected(Error::kInternalError);
    }
    auto loaded = m_slot_manager->LoadCertificate(params.slot_handle, params.client_id);
    if (!loaded.has_value())
    {
        return score::crypto::make_unexpected(loaded.error());
    }
    return RegisterCertMaterial(params, std::move(loaded.value()));
}

score::crypto::Expected<std::monostate, Error> CertManagementService::ReleaseCert(data_manager::ClientId client_id,
                                                                                  data_manager::DataNodeId node_id)
{
    if (!m_data_manager)
    {
        return score::crypto::make_unexpected(Error::kInternalError);
    }
    const auto delete_result = m_data_manager->deleteNode(client_id, node_id);
    if (!delete_result.has_value())
    {
        return score::crypto::make_unexpected(Error::kInvalidResourceId);
    }
    return std::monostate{};
}

void CertManagementService::CleanupClient(data_manager::ClientId client_id)
{
    {
        const std::scoped_lock lock{m_cert_slot_dedup_cache_mutex, m_trust_store_dedup_cache_mutex};
        m_trust_store_dedup_cache.erase(client_id);
        m_cert_slot_dedup_cache.erase(client_id);
    }
    if (m_trust_store_manager)
    {
        m_trust_store_manager->CleanupClient(client_id);
    }
    m_cert_registry->CleanupClient(client_id);
}

// ---------------------------------------------------------------------------
// Slot mutation — wraps CertSlotManager and notifies trust stores on success
// ---------------------------------------------------------------------------

score::crypto::Expected<std::monostate, Error> CertManagementService::StoreCertificate(CertSlotHandle slot,
                                                                                       data_manager::ClientId client_id,
                                                                                       const CertObject& cert)
{
    if (!m_slot_manager)
    {
        return score::crypto::make_unexpected(Error::kInternalError);
    }
    auto result = m_slot_manager->StoreCertificate(slot, client_id, cert);
    if (result.has_value())
    {
        NotifySlotCertChanged(slot);
    }
    return result;
}

score::crypto::Expected<std::monostate, Error> CertManagementService::ClearSlot(CertSlotHandle slot,
                                                                                data_manager::ClientId client_id)
{
    if (!m_slot_manager)
    {
        return score::crypto::make_unexpected(Error::kInternalError);
    }
    auto result = m_slot_manager->ClearSlot(slot, client_id);
    if (result.has_value())
    {
        NotifySlotCertChanged(slot);
    }
    return result;
}

score::crypto::Expected<std::monostate, Error> CertManagementService::ImportCrl(
    CertSlotHandle slot,
    data_manager::ClientId client_id,
    score::crypto::span<const uint8_t> crl_data,
    score::crypto::FormatType format,
    std::optional<score::crypto::CrlMetadata> metadata)
{
    if (!m_slot_manager)
    {
        return score::crypto::make_unexpected(Error::kInternalError);
    }
    auto result = m_slot_manager->ImportCrl(slot, client_id, crl_data, format, metadata);
    if (result.has_value())
    {
        const CrlData stored{std::vector<uint8_t>(crl_data.begin(), crl_data.end()), format, metadata};
        NotifySlotCrlChanged(slot, stored);
    }
    return result;
}

score::crypto::Expected<std::monostate, Error> CertManagementService::DeleteCrl(CertSlotHandle slot,
                                                                                data_manager::ClientId client_id)
{
    if (!m_slot_manager)
    {
        return score::crypto::make_unexpected(Error::kInternalError);
    }
    auto result = m_slot_manager->DeleteCrl(slot, client_id);
    if (result.has_value())
    {
        NotifySlotCrlChanged(slot, std::nullopt);
    }
    return result;
}

// ---------------------------------------------------------------------------
// Resource resolution — mediator resource resolvers
// ---------------------------------------------------------------------------

score::crypto::Expected<data_manager::DataNodeId, Error> CertManagementService::ResolveCertSlot(
    const std::string& resource_name,
    data_manager::ClientId client_id)
{
    if (!m_data_manager || !m_slot_registry)
    {
        return score::crypto::make_unexpected(Error::kInternalError);
    }

    auto handle_res = m_slot_registry->ResolveAppResource(resource_name, client_id);
    if (!handle_res.has_value())
    {
        return score::crypto::make_unexpected(handle_res.error());
    }

    return ResolveCertSlot(handle_res.value(), client_id);
}

score::crypto::Expected<data_manager::DataNodeId, Error> CertManagementService::ResolveCertSlot(
    CertSlotHandle slot_handle,
    data_manager::ClientId client_id)
{
    if (!m_data_manager || !m_slot_registry)
    {
        return score::crypto::make_unexpected(Error::kInternalError);
    }
    if (!m_slot_registry->GetConfig(slot_handle).has_value())
    {
        return score::crypto::make_unexpected(Error::kInvalidResourceId);
    }

    const std::lock_guard lock{m_cert_slot_dedup_cache_mutex};
    auto& client_cache = m_cert_slot_dedup_cache[client_id];
    const auto it = client_cache.find(slot_handle.index);
    if (it != client_cache.end())
    {
        return it->second;
    }

    auto node = std::make_shared<CertSlotDataNode>(slot_handle, m_slot_registry);
    auto node_id = m_data_manager->addNode(client_id, std::move(node));
    if (!node_id.has_value())
    {
        return score::crypto::make_unexpected(Error::kInternalError);
    }

    client_cache[slot_handle.index] = node_id.value();
    return node_id.value();
}

score::crypto::Expected<data_manager::DataNodeId, Error> CertManagementService::ResolveTrustStore(
    const std::string& resource_name,
    data_manager::ClientId client_id)
{
    if (!m_data_manager || !m_trust_store_manager)
    {
        return score::crypto::make_unexpected(Error::kInternalError);
    }

    auto handle_res = m_trust_store_manager->ResolveAppResource(resource_name, client_id);
    if (!handle_res.has_value())
    {
        return score::crypto::make_unexpected(handle_res.error());
    }

    const std::lock_guard lock{m_trust_store_dedup_cache_mutex};
    auto& client_cache = m_trust_store_dedup_cache[client_id];
    const auto it = client_cache.find(handle_res.value().index);
    if (it != client_cache.end())
    {
        return it->second;
    }

    auto node = std::make_shared<TrustStoreDataNode>(handle_res.value(), m_trust_store_manager);
    auto node_id = m_data_manager->addNode(client_id, std::move(node));
    if (!node_id.has_value())
    {
        return score::crypto::make_unexpected(Error::kInternalError);
    }

    client_cache[handle_res.value().index] = node_id.value();
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
    {
        return score::crypto::make_unexpected(Error::kInternalError);
    }

    auto acc_res = m_data_manager->getNodeAccessor(client_id, slot_node_id);
    if (!acc_res.has_value())
    {
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }

    auto typed_res = std::move(acc_res).value().downCast<CertSlotDataNode>();
    if (!typed_res.has_value())
    {
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }

    auto& slot_node = *typed_res.value();
    const auto handle = slot_node.GetSlotHandle();
    auto config_res = m_slot_registry->GetConfig(handle);
    if (!config_res.has_value())
    {
        return score::crypto::make_unexpected(config_res.error());
    }

    return ResolvedCertSlot{handle, std::cref(*config_res.value())};
}

score::crypto::Expected<CertObject::Sptr, Error> CertManagementService::ResolveCertForOperation(
    data_manager::ClientId client_id,
    data_manager::DataNodeId cert_node_id)
{
    auto res = ResolveCertWithOptionalCrlMetadata(client_id, cert_node_id, /*include_crl_metadata=*/false);
    if (!res.has_value())
    {
        return score::crypto::make_unexpected(res.error());
    }
    return res.value().cert;
}

score::crypto::Expected<ResolvedCertWithCrlMetadata, Error>
CertManagementService::ResolveCertWithCrlMetadataForOperation(data_manager::ClientId client_id,
                                                              data_manager::DataNodeId cert_node_id)
{
    return ResolveCertWithOptionalCrlMetadata(client_id, cert_node_id, /*include_crl_metadata=*/true);
}

score::crypto::Expected<ResolvedCertWithCrlMetadata, Error> CertManagementService::ResolveCertWithOptionalCrlMetadata(
    data_manager::ClientId client_id,
    data_manager::DataNodeId cert_node_id,
    bool include_crl_metadata)
{
    if (!m_data_manager)
    {
        return score::crypto::make_unexpected(Error::kInternalError);
    }

    auto acc_res = m_data_manager->getNodeAccessor(client_id, cert_node_id);
    if (!acc_res.has_value())
    {
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }

    auto accessor = std::move(acc_res).value();
    if (accessor->GetNodeType() == data_manager::DataNodeType::kCertData)
    {
        auto typed_res = std::move(accessor).downCast<CertDataNode>();
        if (!typed_res.has_value() || !typed_res.value()->GetCertInstance())
        {
            return score::crypto::make_unexpected(Error::kInvalidArgument);
        }
        auto& instance = *typed_res.value()->GetCertInstance();

        std::optional<score::crypto::CrlMetadata> crl_metadata;
        if (include_crl_metadata)
        {
            crl_metadata = instance.GetSessionCrlMetadata();
            if (!crl_metadata.has_value() && instance.GetSlotHandle().IsValid() && m_slot_manager)
            {
                crl_metadata = m_slot_manager->GetCrlMetadata(instance.GetSlotHandle());
            }
        }

        return ResolvedCertWithCrlMetadata{instance.GetCertObject(), crl_metadata};
    }

    if (accessor->GetNodeType() != data_manager::DataNodeType::kCertSlot)
    {
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }
    auto slot_res = std::move(accessor).downCast<CertSlotDataNode>();
    if (!slot_res.has_value() || !m_slot_manager)
    {
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }

    const auto handle = slot_res.value()->GetSlotHandle();
    auto loaded = m_slot_manager->LoadCertificate(handle, client_id);
    if (!loaded.has_value())
    {
        return score::crypto::make_unexpected(loaded.error());
    }
    std::optional<score::crypto::CrlMetadata> crl_metadata;
    if (include_crl_metadata)
    {
        crl_metadata = m_slot_manager->GetCrlMetadata(handle);
    }
    return ResolvedCertWithCrlMetadata{std::move(loaded.value()), crl_metadata};
}

score::crypto::Expected<CertInstance, Error> CertManagementService::ResolveCertInstanceForOperation(
    data_manager::ClientId client_id,
    data_manager::DataNodeId cert_node_id)
{
    if (!m_data_manager)
    {
        return score::crypto::make_unexpected(Error::kInternalError);
    }

    auto acc_res = m_data_manager->getNodeAccessor(client_id, cert_node_id);
    if (!acc_res.has_value())
    {
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }

    auto typed_res = std::move(acc_res).value().downCast<CertDataNode>();
    if (!typed_res.has_value())
    {
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }
    auto instance = typed_res.value()->GetCertInstance();
    if (!instance)
    {
        return score::crypto::make_unexpected(Error::kInternalError);
    }
    return instance;
}

score::crypto::Expected<std::optional<CrlData>, Error> CertManagementService::ResolveCrlForOperation(
    data_manager::ClientId client_id,
    data_manager::DataNodeId cert_node_id)
{
    if (!m_slot_manager)
    {
        return score::crypto::make_unexpected(Error::kInternalError);
    }

    std::optional<CertSlotHandle> source_slot;

    // Not a CertDataNode is not an error here — falls through to the direct-slot case below.
    auto instance_res = ResolveCertInstanceForOperation(client_id, cert_node_id);
    if (instance_res.has_value())
    {
        auto& instance = *instance_res.value();
        auto session_crl = instance.GetSessionCrlSnapshot();
        if (session_crl.has_value())
        {
            auto crl = std::move(session_crl.value());
            return CrlData{std::move(crl.bytes), crl.format, std::move(crl.metadata)};
        }
        if (instance.GetSlotHandle().IsValid())
        {
            source_slot = instance.GetSlotHandle();
        }
    }

    if (!source_slot.has_value())
    {
        auto slot_res = ResolveSlotForOperation(client_id, cert_node_id);
        if (slot_res.has_value())
            source_slot = slot_res.value().handle;
    }

    if (!source_slot.has_value())
    {
        return std::nullopt;
    }

    const auto has_crl = m_slot_manager->HasCrl(*source_slot);
    if (!has_crl.has_value())
    {
        return score::crypto::make_unexpected(has_crl.error());
    }
    if (!has_crl.value())
    {
        return std::nullopt;
    }

    auto crl = m_slot_manager->LoadCrl(*source_slot, client_id);
    if (!crl.has_value())
    {
        return score::crypto::make_unexpected(crl.error());
    }

    return CrlData{std::move(crl.value()),
                   m_slot_manager->GetCrlFormat(*source_slot),
                   m_slot_manager->GetCrlMetadata(*source_slot)};
}

score::crypto::Expected<TrustStoreHandle, Error> CertManagementService::ResolveTrustStoreForOperation(
    data_manager::ClientId client_id,
    data_manager::DataNodeId ts_node_id)
{
    if (!m_data_manager)
    {
        return score::crypto::make_unexpected(Error::kInternalError);
    }

    auto acc_res = m_data_manager->getNodeAccessor(client_id, ts_node_id);
    if (!acc_res.has_value())
    {
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }

    auto typed_res = std::move(acc_res).value().downCast<TrustStoreDataNode>();
    if (!typed_res.has_value())
    {
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }

    return typed_res.value()->GetTrustStoreHandle();
}

void CertManagementService::NotifySlotCertChanged(CertSlotHandle slot_handle)
{
    if (!m_trust_store_manager)
    {
        return;
    }
    const auto memberships = m_trust_store_manager->GetMembershipsForSlot(slot_handle);
    for (const auto ts_handle : memberships)
    {
        m_trust_store_manager->NotifySlotChanged(ts_handle, slot_handle);
    }
}

void CertManagementService::NotifySlotCrlChanged(CertSlotHandle slot_handle, const std::optional<CrlData>& data)
{
    if (!m_trust_store_manager)
    {
        return;
    }
    const auto memberships = m_trust_store_manager->GetMembershipsForSlot(slot_handle);
    for (const auto ts_handle : memberships)
    {
        m_trust_store_manager->NotifySlotCrlChanged(ts_handle, slot_handle, data);
    }
}

}  // namespace score::crypto::daemon::cert_management

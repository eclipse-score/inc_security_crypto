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

score::crypto::Expected<RegisteredCert, Error> CertManagementService::RegisterCertificate(
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
    return RegisteredCert{node_id.value(), std::move(instance)};
}

score::crypto::Expected<RegisteredCert, Error> CertManagementService::LoadCertificate(
    const CertRegistrationParams& params)
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
    return RegisterCertificate(params, std::move(loaded.value()));
}

score::crypto::Expected<std::monostate, Error> CertManagementService::ReleaseCertificate(
    data_manager::ClientId client_id,
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
// Slot mutation — wraps CertSlotManager and notifies trust stores after each write that reaches the backend
// ---------------------------------------------------------------------------

score::crypto::Expected<std::monostate, Error> CertManagementService::UpdateSlot(CertSlotHandle slot,
                                                                                 data_manager::ClientId client_id,
                                                                                 const CertObject& cert)
{
    if (!m_slot_manager)
    {
        return score::crypto::make_unexpected(Error::kInternalError);
    }
    bool content_may_have_changed{false};
    auto result = m_slot_manager->StoreCertificate(slot, client_id, cert, &content_may_have_changed);
    // Refused and handler-less writes leave the stored content unchanged, so trust stores are not reloaded.
    if (content_may_have_changed)
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
    bool content_may_have_changed{false};
    auto result = m_slot_manager->ClearSlot(slot, client_id, &content_may_have_changed);
    // Refused and handler-less writes leave the stored content unchanged, so trust stores are not reloaded.
    if (content_may_have_changed)
    {
        NotifySlotCertChanged(slot);
    }
    return result;
}

score::crypto::Expected<std::monostate, Error> CertManagementService::UpdateSlot(CertSlotHandle slot,
                                                                                 data_manager::ClientId client_id,
                                                                                 const CrlData& crl)
{
    if (!m_slot_manager)
    {
        return score::crypto::make_unexpected(Error::kInternalError);
    }
    bool content_may_have_changed{false};
    auto result = m_slot_manager->StoreCrl(slot, client_id, crl, &content_may_have_changed);
    // Refused and handler-less writes leave the stored CRL unchanged, so trust stores are not reloaded.
    if (content_may_have_changed)
    {
        NotifySlotCrlChanged(slot);
    }
    return result;
}

score::crypto::Expected<std::monostate, Error> CertManagementService::ClearSlotCrl(CertSlotHandle slot,
                                                                                   data_manager::ClientId client_id)
{
    if (!m_slot_manager)
    {
        return score::crypto::make_unexpected(Error::kInternalError);
    }
    bool content_may_have_changed{false};
    auto result = m_slot_manager->ClearCrl(slot, client_id, &content_may_have_changed);
    // Refused and handler-less writes leave the stored CRL unchanged, so trust stores are not reloaded.
    if (content_may_have_changed)
    {
        NotifySlotCrlChanged(slot);
    }
    return result;
}

// ---------------------------------------------------------------------------
// Resource resolution — mediator resource resolvers
// ---------------------------------------------------------------------------

score::crypto::Expected<data_manager::DataNodeId, Error> CertManagementService::ResolveCertSlotNode(
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

    return ResolveCertSlotNode(handle_res.value(), client_id);
}

score::crypto::Expected<data_manager::DataNodeId, Error> CertManagementService::ResolveCertSlotNode(
    CertSlotHandle slot_handle,
    data_manager::ClientId client_id)
{
    if (!m_data_manager || !m_slot_registry)
    {
        return score::crypto::make_unexpected(Error::kInternalError);
    }
    if (!m_slot_registry->IsValidHandle(slot_handle))
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

score::crypto::Expected<data_manager::DataNodeId, Error> CertManagementService::ResolveTrustStoreNode(
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

score::crypto::Expected<CertSlotHandle, Error> CertManagementService::ResolveCertSlotHandle(
    data_manager::ClientId client_id,
    data_manager::DataNodeId slot_node_id)
{
    if (!m_data_manager || !m_slot_registry)
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

    const auto handle = typed_res.value()->GetSlotHandle();
    if (!m_slot_registry->IsValidHandle(handle))
    {
        return score::crypto::make_unexpected(Error::kInvalidResourceId);
    }
    return handle;
}

score::crypto::Expected<CertObject::Sptr, Error> CertManagementService::ResolveCertObject(
    data_manager::ClientId client_id,
    data_manager::DataNodeId cert_node_id)
{
    auto res = ResolveCertObjectWithOptionalCrlMetadata(client_id, cert_node_id, /*include_crl_metadata=*/false);
    if (!res.has_value())
    {
        return score::crypto::make_unexpected(res.error());
    }
    return res.value().cert;
}

score::crypto::Expected<ResolvedCertObjectWithCrlMetadata, Error>
CertManagementService::ResolveCertObjectWithCrlMetadata(data_manager::ClientId client_id,
                                                        data_manager::DataNodeId cert_node_id)
{
    return ResolveCertObjectWithOptionalCrlMetadata(client_id, cert_node_id, /*include_crl_metadata=*/true);
}

score::crypto::Expected<ResolvedCertObjectWithCrlMetadata, Error>
CertManagementService::ResolveCertObjectWithOptionalCrlMetadata(data_manager::ClientId client_id,
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
            if (const auto session_crl = instance.GetSessionCrlSnapshot())
            {
                crl_metadata = session_crl->metadata;
            }
            if (!crl_metadata.has_value() && instance.GetSlotHandle().IsValid() && m_slot_manager)
            {
                const auto metadata = m_slot_manager->GetCrlMetadata(instance.GetSlotHandle(), client_id);
                if (!metadata.has_value())
                {
                    return score::crypto::make_unexpected(metadata.error());
                }
                crl_metadata = metadata.value();
            }
        }

        return ResolvedCertObjectWithCrlMetadata{instance.GetCertObject(), crl_metadata};
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
        const auto metadata = m_slot_manager->GetCrlMetadata(handle, client_id);
        if (!metadata.has_value())
        {
            return score::crypto::make_unexpected(metadata.error());
        }
        crl_metadata = metadata.value();
    }
    return ResolvedCertObjectWithCrlMetadata{std::move(loaded.value()), crl_metadata};
}

score::crypto::Expected<std::shared_ptr<CertEntry>, Error> CertManagementService::ResolveCertEntry(
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

score::crypto::Expected<CrlData::Sptrc, Error> CertManagementService::ResolveCrlData(
    data_manager::ClientId client_id,
    data_manager::DataNodeId cert_node_id)
{
    if (!m_slot_manager)
    {
        return score::crypto::make_unexpected(Error::kInternalError);
    }

    std::optional<CertSlotHandle> source_slot;
    // The node is recognised when it resolves as a certificate or as a certificate slot.
    bool recognised = false;

    // A node that is not a certificate is not an error here; it falls through to the slot case below.
    auto instance_res = ResolveCertEntry(client_id, cert_node_id);
    if (instance_res.has_value())
    {
        recognised = true;
        auto& instance = *instance_res.value();
        if (auto session_crl = instance.GetSessionCrlSnapshot())
        {
            return session_crl;
        }
        if (instance.GetSlotHandle().IsValid())
        {
            source_slot = instance.GetSlotHandle();
        }
    }

    if (!source_slot.has_value())
    {
        auto slot_res = ResolveCertSlotHandle(client_id, cert_node_id);
        if (slot_res.has_value())
        {
            recognised = true;
            source_slot = slot_res.value();
        }
    }

    if (!recognised)
    {
        return score::crypto::make_unexpected(Error::kInvalidResourceId);
    }

    // A recognised certificate with no session CRL and no slot, such as an ephemeral certificate, has no CRL.
    if (!source_slot.has_value())
    {
        return CrlData::Sptrc{};
    }

    return m_slot_manager->LoadCrlData(*source_slot, client_id);
}

score::crypto::Expected<TrustStoreHandle, Error> CertManagementService::ResolveTrustStoreHandle(
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
    m_trust_store_manager->NotifySlotChanged(slot_handle);
}

void CertManagementService::NotifySlotCrlChanged(CertSlotHandle slot_handle)
{
    if (!m_trust_store_manager)
    {
        return;
    }
    m_trust_store_manager->NotifySlotCrlChanged(slot_handle);
}

}  // namespace score::crypto::daemon::cert_management

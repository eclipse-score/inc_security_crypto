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
#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CORE_CERT_MANAGEMENT_SERVICE_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CORE_CERT_MANAGEMENT_SERVICE_HPP

#include "score/crypto/src/daemon/cert_management/core/cert_registry.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/i_cert_slot_handler.hpp"
#include "score/crypto/src/daemon/cert_management/nodes/cert_data_node.hpp"
#include "score/crypto/src/daemon/cert_management/truststore/trust_store_manager.hpp"
#include "score/crypto/src/daemon/data_manager/i_data_manager.hpp"

#include <memory>
#include <unordered_map>

namespace score::crypto::daemon::cert_management
{
struct CertDataNodeResult
{
    data_manager::DataNodeId node_id{};
    std::shared_ptr<CertEntry> entry;
};

/// Resolved certificate slot — handler + config + handle returned by ResolveSlotForOperation.
struct ResolvedCertSlot
{
    CertSlotHandle handle;
    const CertSlotConfig* config{nullptr};
    ICertSlotHandler::Sptr handler;
};

class CertManagementService final
{
  public:
    using Sptr = std::shared_ptr<CertManagementService>;

    CertManagementService(data_manager::IDataManager::Sptr data_manager,
                          CertSlotRegistry::Sptr slot_registry,
                          TrustStoreManager::Sptr trust_store_manager,
                          CertSlotHandlerFactory slot_handler_factory = {});

    // -----------------------------------------------------------------------
    // Existing cert lifecycle methods
    // -----------------------------------------------------------------------

    score::crypto::Expected<CertDataNodeResult, common::DaemonErrorCode> RegisterCertMaterial(
        const CertRegistrationParams&,
        CertObject::Sptr);
    score::crypto::Expected<CertDataNodeResult, common::DaemonErrorCode> LoadOrShare(const CertRegistrationParams&,
                                                                                     ICertSlotHandler&,
                                                                                     const CertSlotConfig&);
    score::crypto::Expected<std::monostate, common::DaemonErrorCode> ReleaseCert(data_manager::ClientId,
                                                                                 data_manager::DataNodeId);
    void CleanupClient(data_manager::ClientId);

    TrustStoreManager::Sptr GetTrustStoreManager() const
    {
        return m_trust_stores;
    }

    // -----------------------------------------------------------------------
    // Resource resolution — called by mediator resource resolvers
    // -----------------------------------------------------------------------

    /// Resolve an application cert slot resource name to a client-scoped DataNodeId.
    ///
    /// Creates a CertSlotDataNode under the client root in the data manager.
    /// The node survives across context opens, matching key slot lifecycle.
    score::crypto::Expected<data_manager::DataNodeId, common::DaemonErrorCode> ResolveCertSlot(
        const std::string& resource_name,
        data_manager::ClientId client_id);

    /// Resolve an application trust store resource name to a client-scoped DataNodeId.
    ///
    /// Creates a TrustStoreDataNode under the client root in the data manager.
    score::crypto::Expected<data_manager::DataNodeId, common::DaemonErrorCode> ResolveTrustStore(
        const std::string& resource_name,
        data_manager::ClientId client_id);

    // -----------------------------------------------------------------------
    // Operation helpers — called by the cert management executor
    // -----------------------------------------------------------------------

    /// Look up a CertSlotDataNode by node_id and return its slot config + handler.
    score::crypto::Expected<ResolvedCertSlot, common::DaemonErrorCode> ResolveSlotForOperation(
        data_manager::ClientId client_id,
        data_manager::DataNodeId slot_node_id);

    /// Look up a CertDataNode by node_id and return the underlying CertObject.
    score::crypto::Expected<CertObject::Sptr, common::DaemonErrorCode> ResolveCertForOperation(
        data_manager::ClientId client_id,
        data_manager::DataNodeId cert_node_id);

    /// Look up a TrustStoreDataNode by node_id and return the trust store handle.
    score::crypto::Expected<TrustStoreHandle, common::DaemonErrorCode> ResolveTrustStoreForOperation(
        data_manager::ClientId client_id,
        data_manager::DataNodeId ts_node_id);

    /// Fan out NotifyUpdate() to all trust stores referencing the given cert slot.
    ///
    /// Called after a successful StoreCertificate to keep trust store anchors current.
    void NotifySlotCertChanged(CertSlotHandle slot_handle);

  private:
    data_manager::IDataManager::Sptr m_data_manager;
    CertSlotRegistry::Sptr m_slot_registry;
    TrustStoreManager::Sptr m_trust_stores;
    CertRegistry m_cert_registry;
    CertSlotHandlerFactory m_slot_handler_factory;

    // Node-id dedup caches — keyed by (client_id, resource_name).
    // Mirrors the key-slot dedup pattern so that resolving the same resource
    // twice from the same client reuses the existing DataNodeId.
    std::unordered_map<data_manager::ClientId, std::unordered_map<std::string, data_manager::DataNodeId>>
        m_cert_slot_node_cache;
    std::unordered_map<data_manager::ClientId, std::unordered_map<std::string, data_manager::DataNodeId>>
        m_trust_store_node_cache;
};
}  // namespace score::crypto::daemon::cert_management
#endif

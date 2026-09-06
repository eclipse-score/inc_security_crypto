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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_NODES_TRUST_STORE_DATA_NODE_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_NODES_TRUST_STORE_DATA_NODE_HPP

#include "score/crypto/src/daemon/cert_management/interfaces/cert_types.hpp"
#include "score/crypto/src/daemon/cert_management/truststore/trust_store_manager.hpp"
#include "score/crypto/src/daemon/data_manager/data_node.hpp"

namespace score::crypto::daemon::cert_management
{

/// Application-scoped reference to a manager-owned trust store.
///
/// Lightweight handle node — holds only a TrustStoreHandle, analogous to
/// CertSlotDataNode for cert slots. Cert content is NOT loaded or cached here.
///
/// Lifetime: parented under the root connection node; survives for the full
/// application connection, not just for a single verification operation.
class TrustStoreDataNode final : public data_manager::DataNode
{
  public:
    TrustStoreDataNode(TrustStoreHandle handle, TrustStoreManager::Sptr manager)
        : DataNode(false), m_handle{handle}, m_manager{std::move(manager)}
    {
    }

    data_manager::DataNodeType GetNodeType() const noexcept override
    {
        return data_manager::DataNodeType::kTrustStore;
    }

    TrustStoreHandle GetTrustStoreHandle() const noexcept
    {
        return m_handle;
    }

    TrustStoreManager::Sptr GetTrustStoreManager() const
    {
        return m_manager;
    }

    ITrustStoreHandler::Sptr GetStore() const
    {
        return m_manager ? m_manager->GetStore(m_handle) : nullptr;
    }

  private:
    TrustStoreHandle m_handle;
    TrustStoreManager::Sptr m_manager;
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_NODES_TRUST_STORE_DATA_NODE_HPP

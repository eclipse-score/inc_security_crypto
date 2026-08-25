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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_NODES_CERT_DATA_NODE_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_NODES_CERT_DATA_NODE_HPP

#include "score/crypto/src/daemon/cert_management/core/cert_entry.hpp"
#include "score/crypto/src/daemon/cert_management/core/cert_registry.hpp"
#include "score/crypto/src/daemon/data_manager/data_node.hpp"

#include <cstdint>
#include <functional>
#include <memory>

namespace score::crypto::daemon::cert_management
{

/// DataNode placed in the client's tree that references a shared CertEntry
/// living in the per-provider CertRegistry.
///
/// On construction, increments the CertEntry's reference count.
/// On destruction, decrements it. When the count reaches zero, the provided
/// cleanup callback unregisters the cert from the registry.
///
/// exclusiveAccess = false: multiple threads may read concurrently.
class CertDataNode final : public data_manager::DataNode
{
  public:
    using UnregisterCallback = std::function<void(CertRegistryId)>;

    [[nodiscard]] data_manager::DataNodeType GetNodeType() const noexcept override
    {
        return data_manager::DataNodeType::kCertData;
    }

    CertDataNode(std::shared_ptr<CertEntry> cert_entry,
                 CertRegistryId registry_id,
                 data_manager::ClientId client_id,
                 UnregisterCallback on_last_release)
        : DataNode(false),
          m_cert_entry{std::move(cert_entry)},
          m_registry_id{registry_id},
          m_client_id{client_id},
          m_on_last_release{std::move(on_last_release)}
    {
        m_cert_entry->AddRef(m_client_id);
    }

    ~CertDataNode() override
    {
        if (m_cert_entry != nullptr)
        {
            const bool last = m_cert_entry->Release(m_client_id);
            if (last && m_on_last_release)
            {
                m_on_last_release(m_registry_id);
            }
        }
    }

    CertDataNode(const CertDataNode&) = delete;
    CertDataNode& operator=(const CertDataNode&) = delete;
    CertDataNode(CertDataNode&&) = delete;
    CertDataNode& operator=(CertDataNode&&) = delete;

    [[nodiscard]] std::shared_ptr<CertEntry> GetCertEntry() const noexcept
    {
        return m_cert_entry;
    }

    [[nodiscard]] CertRegistryId GetRegistryId() const noexcept
    {
        return m_registry_id;
    }

  private:
    std::shared_ptr<CertEntry> m_cert_entry;
    CertRegistryId m_registry_id;
    data_manager::ClientId m_client_id;
    UnregisterCallback m_on_last_release;
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_NODES_CERT_DATA_NODE_HPP

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
#include <memory>
#include <utility>

namespace score::crypto::daemon::cert_management
{

/// DataNode placed in the client's tree that references a shared CertEntry
/// instance and keeps its CertRegistry alive for unregistering on destruction.
///
/// The registry and node share ownership of the CertEntry. On destruction,
/// the node unregisters its entry from the registry.
///
/// exclusiveAccess = false: multiple threads may read concurrently.
class CertDataNode final : public data_manager::DataNode
{
  public:
    /// @brief Returns the data manager node type for certificate data.
    [[nodiscard]] data_manager::DataNodeType GetNodeType() const noexcept override
    {
        return data_manager::DataNodeType::kCertData;
    }

    /// @brief Create a client-scoped reference to a registered certificate.
    /// @param cert_instance Certificate instance retained by the node.
    /// @param cert_registry Registry used to unregister the entry when the node is destroyed; must not be null.
    /// @param registry_id Identifier returned by the registry when the certificate was registered.
    /// @param client_id Client that owns this node.
    CertDataNode(std::shared_ptr<CertEntry> cert_instance,
                 CertRegistry::Sptr cert_registry,
                 CertRegistryId registry_id,
                 data_manager::ClientId client_id)
        : DataNode(false),
          m_cert_instance{std::move(cert_instance)},
          m_cert_registry{std::move(cert_registry)},
          m_registry_id{registry_id},
          m_client_id{client_id}
    {
    }

    /// @brief Unregisters the certificate entry from the registry.
    ~CertDataNode() override
    {
        m_cert_registry->Unregister(m_registry_id);
    }

    /// Not copyable or movable; the registry entry is tied to this node's lifetime.
    CertDataNode(const CertDataNode&) = delete;
    CertDataNode& operator=(const CertDataNode&) = delete;
    CertDataNode(CertDataNode&&) = delete;
    CertDataNode& operator=(CertDataNode&&) = delete;

    /// @brief Shared certificate instance held by this node.
    [[nodiscard]] std::shared_ptr<CertEntry> GetCertInstance() const noexcept
    {
        return m_cert_instance;
    }

    /// @brief Identifier under which the entry is registered.
    [[nodiscard]] CertRegistryId GetRegistryId() const noexcept
    {
        return m_registry_id;
    }

  private:
    std::shared_ptr<CertEntry> m_cert_instance;
    CertRegistry::Sptr m_cert_registry;
    CertRegistryId m_registry_id;
    data_manager::ClientId m_client_id;
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_NODES_CERT_DATA_NODE_HPP

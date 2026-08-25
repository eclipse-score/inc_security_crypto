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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_NODES_CERT_SLOT_DATA_NODE_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_NODES_CERT_SLOT_DATA_NODE_HPP

#include "score/crypto/src/daemon/cert_management/interfaces/cert_slot_config.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_types.hpp"
#include "score/crypto/src/daemon/cert_management/slot/slot_registry.hpp"
#include "score/crypto/src/daemon/data_manager/data_node.hpp"

#include <memory>

namespace score::crypto::daemon::cert_management
{

/// DataNode for a resolved persistent certificate slot.
///
/// Created on ResolveResource(), lives for the connection lifetime.
/// Holds only a lightweight CertSlotHandle and a reference to the CertSlotRegistry.
/// exclusiveAccess = false (concurrent reads OK).
class CertSlotDataNode : public data_manager::DataNode
{
  public:
    CertSlotDataNode(CertSlotHandle slot_handle, CertSlotRegistry::Sptr slot_registry)
        : DataNode(false), m_slot_handle{slot_handle}, m_slot_registry{std::move(slot_registry)}
    {
    }

    ~CertSlotDataNode() override = default;

    [[nodiscard]] data_manager::DataNodeType GetNodeType() const noexcept override
    {
        return data_manager::DataNodeType::kCertSlot;
    }

    [[nodiscard]] CertSlotHandle GetSlotHandle() const noexcept
    {
        return m_slot_handle;
    }

    /// @brief Access config from central registry.
    [[nodiscard]] score::crypto::Expected<const CertSlotConfig*, score::crypto::daemon::common::DaemonErrorCode>
    GetConfig() const
    {
        return m_slot_registry->GetConfig(m_slot_handle);
    }

    [[nodiscard]] CertSlotRegistry::Sptr GetSlotRegistry() const
    {
        return m_slot_registry;
    }

  private:
    CertSlotHandle m_slot_handle;
    CertSlotRegistry::Sptr m_slot_registry;
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_NODES_CERT_SLOT_DATA_NODE_HPP

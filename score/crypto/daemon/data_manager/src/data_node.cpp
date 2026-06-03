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

#include "score/mw/log/logging.h"
#include <algorithm>

#include <memory>
#include <variant>
#include <vector>

#include "score/crypto/common/types.hpp"
#include "score/crypto/daemon/common/daemon_error.hpp"
#include "score/crypto/daemon/data_manager/data_node.hpp"

namespace score::crypto::daemon::data_manager
{

// Default constructor uses default initialization for members
// DataNodeId is initialized by DataManager via SetNodeId()

DataNode::DataNode(bool exclusiveAccess) : m_exclusiveAccess(exclusiveAccess) {}

DataNodeId DataNode::getNodeId() const
{
    return m_nodeId;
}

void DataNode::setNodeId(DataNodeId nodeId, const DataNodeManagerToken& /*token*/)
{
    m_nodeId = nodeId;
}

void DataNode::setParent(const std::weak_ptr<DataNode>& parent, const DataNodeManagerToken& /*token*/)
{
    // Since we expect the DataNodeManagerToken, DataManager is responsible for thread safety
    m_parent = parent;
}

ClientId DataNode::getClientId() const
{
    return m_client_id;
}

void DataNode::setClientId(ClientId clientId, const DataNodeManagerToken& /*token*/)
{
    m_client_id = clientId;
}

Expected<DataNodeId, score::crypto::daemon::common::DaemonErrorCode> DataNode::getParent(
    const DataNodeManagerToken& /*token*/) const
{
    // Since we expect the DataNodeManagerToken, DataManager is responsible for thread safety
    auto parent = m_parent.lock();
    if (!parent)
    {
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidContext);
    }

    return parent->getNodeId();
}

void DataNode::addChild(const std::shared_ptr<DataNode>& child, const DataNodeManagerToken& /*token*/)
{
    // Since we expect the DataNodeManagerToken, DataManager is responsible for thread safety
    m_children.push_back(child);
}

std::vector<DataNodeId> DataNode::getChildren(const DataNodeManagerToken& /*token*/) const
{
    // Since we expect the DataNodeManagerToken, DataManager is responsible for thread safety
    std::vector<DataNodeId> child_ids;
    child_ids.reserve(m_children.size());
    for (const auto& child : m_children)
    {
        child_ids.push_back(child->getNodeId());
    }

    return child_ids;
}

Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> DataNode::removeChild(
    DataNodeId nodeId,
    const DataNodeManagerToken& /*token*/)
{
    // Since we expect the DataNodeManagerToken, DataManager is responsible for thread safety
    auto child = std::find_if(m_children.begin(), m_children.end(), [nodeId](const DataNode::Sptr& child_itr) {
        return nodeId == child_itr->getNodeId();
    });
    if (child != m_children.end())
    {
        m_children.erase(child);
    }
    else
    {
        score::mw::log::LogError() << LOG_PREFIX << "removeChild could not find child with nodeId:" << nodeId;
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    return {};
}

bool DataNode::requiresExclusiveAccess() const
{
    // m_exclusiveAccess is const, no need to lock mutex
    return m_exclusiveAccess;
}

}  // namespace score::crypto::daemon::data_manager

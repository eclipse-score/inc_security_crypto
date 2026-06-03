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
#include <cassert>
#include <cstddef>

#include <memory>
#include <mutex>
#include <utility>
#include <variant>
#include <vector>

#include "score/crypto/common/types.hpp"
#include "score/crypto/daemon/common/daemon_error.hpp"
#include "score/crypto/daemon/data_manager/data_manager.hpp"
#include "score/crypto/daemon/data_manager/data_node.hpp"
#include "score/crypto/daemon/data_manager/data_node_accessor.hpp"
#include "score/crypto/daemon/data_manager/i_data_manager.hpp"
#include "score/crypto/daemon/data_manager/src/data_node_manager_token.hpp"

namespace score::crypto::daemon::data_manager
{

Expected<DataNodeId, score::crypto::daemon::common::DaemonErrorCode> DataManager::addNode(
    ClientId clientId,
    std::shared_ptr<DataNode> node)
{
    score::mw::log::LogDebug() << LOG_PREFIX << "addNode for clientId:" << clientId;

    if (!node)
    {
        score::mw::log::LogError() << LOG_PREFIX << "addNode: Invalid node sptr";
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    const std::lock_guard<std::mutex> lock(m_mutex);

    auto nodeIdRes = getNextNodeIdLocked(clientId, lock);
    if (!nodeIdRes)
    {
        score::mw::log::LogError() << LOG_PREFIX << "addNode: Could not get a nodeId";
        return make_unexpected(nodeIdRes.error());
    }
    auto nodeId = nodeIdRes.value();

    // Only DataManager may mutate these fields; pass access token
    node->setNodeId(nodeId, DataNodeManagerToken{});
    node->setClientId(clientId, DataNodeManagerToken{});

    m_node_map.try_emplace(clientId).first->second.emplace(nodeId, node);
    m_entry_nodes_per_client.try_emplace(clientId).first->second.push_back(nodeId);

    score::mw::log::LogDebug() << LOG_PREFIX << "addNode new nodeId:" << nodeId;

    return nodeId;
}

Expected<DataNodeId, score::crypto::daemon::common::DaemonErrorCode>
DataManager::addChildNode(ClientId clientId, DataNodeId parentId, std::shared_ptr<DataNode> node)
{
    score::mw::log::LogDebug() << LOG_PREFIX << "addChildNode for clientId:" << clientId
                               << " with parentId:" << parentId;

    if (!node)
    {
        score::mw::log::LogError() << LOG_PREFIX << "addChildNode: Invalid node sptr";
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    const std::lock_guard<std::mutex> lock(m_mutex);

    auto parentRes = getNodeLocked(clientId, parentId, lock);
    if (!parentRes.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "addChildNode: Failed to get parent";
        return make_unexpected(parentRes.error());
    }
    const auto& parent = parentRes.value();

    auto nodeIdRes = getNextNodeIdLocked(clientId, lock);
    if (!nodeIdRes)
    {
        score::mw::log::LogError() << LOG_PREFIX << "addChildNode: Could not get a nodeId";
        return make_unexpected(nodeIdRes.error());
    }
    auto nodeId = nodeIdRes.value();

    // Only DataManager may mutate these fields; pass access token
    node->setNodeId(nodeId, DataNodeManagerToken{});
    node->setClientId(clientId, DataNodeManagerToken{});

    parent->addChild(node, DataNodeManagerToken{});
    node->setParent(parent, DataNodeManagerToken{});

    // Since we have parent with the same clientId, the client entry does already exist
    m_node_map.at(clientId).emplace(nodeId, node);

    score::mw::log::LogDebug() << LOG_PREFIX << "addChildNode new nodeId:" << nodeId;

    return nodeId;
}

Expected<DataNodeId, score::crypto::daemon::common::DaemonErrorCode>
DataManager::addSiblingNode(ClientId clientId, DataNodeId siblingId, std::shared_ptr<DataNode> node)
{
    score::mw::log::LogDebug() << LOG_PREFIX << "addSiblingNode for clientId:" << clientId
                               << " with siblingId:" << siblingId;

    if (!node)
    {
        score::mw::log::LogError() << LOG_PREFIX << "addSiblingNode: Invalid node sptr";
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    const std::lock_guard<std::mutex> lock(m_mutex);

    auto siblingRes = getNodeLocked(clientId, siblingId, lock);
    if (!siblingRes.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "addSiblingNode: Failed to get sibling";
        return make_unexpected(siblingRes.error());
    }
    const auto& sibling = siblingRes.value();

    auto parentIdRes = sibling->getParent(DataNodeManagerToken{});
    if (!parentIdRes.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "addSiblingNode: Sibling has no parent";
        return make_unexpected(parentIdRes.error());
    }
    const auto parentId = parentIdRes.value();

    auto parentRes = getNodeLocked(clientId, parentId, lock);
    if (!parentRes.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "addSiblingNode: Failed to get parent";
        return make_unexpected(parentRes.error());
    }
    const auto& parent = parentRes.value();

    auto nodeIdRes = getNextNodeIdLocked(clientId, lock);
    if (!nodeIdRes)
    {
        score::mw::log::LogError() << LOG_PREFIX << "addSiblingNode: Could not get a nodeId";
        return make_unexpected(nodeIdRes.error());
    }
    auto nodeId = nodeIdRes.value();

    // Only DataManager may mutate these fields; pass access token
    node->setNodeId(nodeId, DataNodeManagerToken{});
    node->setClientId(clientId, DataNodeManagerToken{});

    parent->addChild(node, DataNodeManagerToken{});
    node->setParent(parent, DataNodeManagerToken{});

    // Since we have parent with the same clientId, the client entry does already exist
    m_node_map.at(clientId).emplace(nodeId, node);

    score::mw::log::LogDebug() << LOG_PREFIX << "addSiblingNode new nodeId:" << nodeId;

    return nodeId;
}

Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> DataManager::deleteClientNodes(
    ClientId clientId)
{
    score::mw::log::LogDebug() << LOG_PREFIX << "deleteClientNodes for clientId:" << clientId;

    const std::lock_guard<std::mutex> lock(m_mutex);

    Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> result;

    auto clientItr = m_entry_nodes_per_client.find(clientId);
    if (clientItr == m_entry_nodes_per_client.end())
    {
        score::mw::log::LogError() << LOG_PREFIX << "deleteClientNodes: Unknown clientId:" << clientId;
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    // Work on a copy, since the original will be modified during the removal
    auto clientEntryNodes = clientItr->second;
    for (auto entryNodeId : clientEntryNodes)
    {
        auto subResult = removeNodesFromStorage(clientId, entryNodeId, lock);
        if (!subResult.has_value() && result.has_value())
        {
            result = make_unexpected(subResult.error());
        }
    }

    return result;
}

Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> DataManager::deleteNode(ClientId clientId,
                                                                                                 DataNodeId nodeId)
{
    score::mw::log::LogDebug() << LOG_PREFIX << "deleteNode for clientId:" << clientId << " nodeId:" << nodeId;

    const std::lock_guard<std::mutex> lock(m_mutex);
    auto result = removeNodesFromStorage(clientId, nodeId, lock);

    return result;
}

Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
DataManager::removeNodesFromStorage(ClientId clientId, DataNodeId rootNodeId, const std::lock_guard<std::mutex>& _lock)
{
    score::mw::log::LogDebug() << LOG_PREFIX << "removeNodesFromStorage with clientId:" << clientId
                               << " nodeId:" << rootNodeId;

    Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> result{};

    // Single traversal: collect nodes in visit order together with their shared_ptr so we
    // do not look them up a second time during the removal phase.
    std::vector<DataNodeId> stack;
    std::vector<std::pair<DataNodeId, std::shared_ptr<DataNode>>> postOrder;
    stack.push_back(rootNodeId);

    while (!stack.empty())
    {
        const DataNodeId currentId = stack.back();
        stack.pop_back();

        auto nodeRes = getNodeLocked(clientId, currentId, _lock);
        if (!nodeRes.has_value())
        {
            score::mw::log::LogError() << LOG_PREFIX << "removeNodesFromStorage: getNodeLocked failed for node "
                                       << currentId;
            if (result.has_value())
            {
                result = make_unexpected(nodeRes.error());
            }
            continue;
        }

        auto node = std::move(nodeRes).value();

        for (const auto& childId : node->getChildren(DataNodeManagerToken{}))
        {
            stack.push_back(childId);
        }

        postOrder.emplace_back(currentId, std::move(node));
    }

    for (auto it = postOrder.rbegin(); it != postOrder.rend(); ++it)
    {
        const DataNodeId currentId = it->first;
        const auto& node = it->second;

        auto subResult = removeSingleNodeFromStorage(node, clientId, currentId, _lock);
        if (!subResult.has_value() && result.has_value())
        {
            score::mw::log::LogError() << LOG_PREFIX
                                       << "removeNodesFromStorage: removeSingleNodeFromStorage failed for node "
                                       << currentId;
            result = make_unexpected(subResult.error());
        }
    }

    return result;
}

Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> DataManager::removeSingleNodeFromStorage(
    const std::shared_ptr<DataNode>& node,
    ClientId clientId,
    DataNodeId nodeId,
    const std::lock_guard<std::mutex>& _lock)
{
    score::mw::log::LogDebug() << LOG_PREFIX << "removeSingleNodeFromStorage with clientId:" << clientId
                               << " nodeId:" << nodeId;

    Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> result{};

    auto parentId = node->getParent(DataNodeManagerToken{});
    if (parentId.has_value())
    {
        // Remove the current node from its parent to ensure it is deleted first.
        auto parentRes = getNodeLocked(clientId, parentId.value(), _lock);
        if (parentRes.has_value())
        {
            result = parentRes.value()->removeChild(nodeId, DataNodeManagerToken{});
        }
        else
        {
            score::mw::log::LogError() << LOG_PREFIX << "removeNodesFromStorage: getNodeLocked of parent failed "
                                       << parentId.value();
            result = make_unexpected(parentRes.error());
        }
    }
    else
    {
        result = removeEntryNodeFromIndex(clientId, nodeId, _lock);
    }

    auto nodeMapItr = m_node_map.find(clientId);
    if (nodeMapItr != m_node_map.end())
    {
        nodeMapItr->second.erase(nodeId);

        // Remove the whole element if empty
        if (nodeMapItr->second.empty())
        {
            m_node_map.erase(nodeMapItr);
        }
    }
    else
    {
        score::mw::log::LogError() << LOG_PREFIX << "removeSingleNodeFromStorage: Not found: clientId:" << clientId;
        if (result.has_value())
        {
            result = make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
        }
    }
    // This should not be necessary as we do not expect the user to retrieve an node accessor
    // and remove the same node. But to be safe, also remove it from the busy nodes.
    auto busyNodesItr = m_busy_nodes.find(clientId);
    if (busyNodesItr != m_busy_nodes.end())
    {
        busyNodesItr->second.erase(nodeId);

        // Remove the whole element if empty
        if (busyNodesItr->second.empty())
        {
            m_busy_nodes.erase(busyNodesItr);
        }
    }

    return result;
}

Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> DataManager::removeEntryNodeFromIndex(
    ClientId clientId,
    DataNodeId nodeId,
    const std::lock_guard<std::mutex>& /*_lock*/)
{
    score::mw::log::LogDebug() << LOG_PREFIX << "removeEntryNodeFromIndex: ClientId:" << clientId
                               << " nodeId:" << nodeId;
    auto clientItr = m_entry_nodes_per_client.find(clientId);
    if (clientItr == m_entry_nodes_per_client.end())
    {
        score::mw::log::LogError() << LOG_PREFIX << "removeEntryNodeFromIndex: Not found: clientId:" << clientId;
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }
    auto& client = clientItr->second;

    auto nodeItr = std::find(client.begin(), client.end(), nodeId);
    if (nodeItr != client.end())
    {
        client.erase(nodeItr);
    }
    else
    {
        score::mw::log::LogError() << LOG_PREFIX << "removeEntryNodeFromIndex: Not found: nodeId:" << nodeId;
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    // Remove the whole element if empty
    if (client.empty())
    {
        m_entry_nodes_per_client.erase(clientItr);
    }

    return {};
}

Expected<std::shared_ptr<DataNode>, score::crypto::daemon::common::DaemonErrorCode>
DataManager::getNodeLocked(ClientId clientId, DataNodeId nodeId, const std::lock_guard<std::mutex>& /*_lock*/) const
{
    score::mw::log::LogDebug() << LOG_PREFIX << "getNodeLocked: ClientId:" << clientId << " nodeId:" << nodeId;

    auto clientItr = m_node_map.find(clientId);
    if (clientItr == m_node_map.end())
    {
        score::mw::log::LogError() << LOG_PREFIX << "getNodeLocked: Not found: clientId:" << clientId;
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }
    const auto& client = clientItr->second;

    auto node = client.find(nodeId);
    if (node == client.end())
    {
        score::mw::log::LogError() << LOG_PREFIX << "getNodeLocked: Not found: nodeId:" << nodeId;
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    return node->second;
}

Expected<DataNodeId, score::crypto::daemon::common::DaemonErrorCode> DataManager::getNextNodeIdLocked(
    ClientId clientId,
    const std::lock_guard<std::mutex>& /*_lock*/)
{
    DataNodeId nodeId = 0;

    // TODO: Check if implications of N retires is ok in terms of runtime.
    // TODO: This could be configurable. Current value is a gut decision.
    // Retry a fixed number of times to find a free ID
    // Number of retires is based on the maximum number of nodes per client (+1 to find the next free one)
    auto retriesLeft = m_max_nodes_per_client + 1;

    // Ensure the counter entry exists for this client, initialised to 0 if new
    auto [counterIt, _unused] = m_id_counter_per_client.try_emplace(clientId, 1);

    auto clientNodesItr = m_node_map.find(clientId);
    if (clientNodesItr == m_node_map.end())
    {
        // No nodes for this client yet, so the first ID (1) is available
        return counterIt->second;
    }

    while (retriesLeft > 0)
    {
        nodeId = counterIt->second;

        // Check whether this ID is already in use
        if (clientNodesItr->second.find(nodeId) == clientNodesItr->second.end())
        {
            return nodeId;
        }

        // Increment counter; wrap around to 1 when exceeding the maximum
        counterIt->second += 1;
        if (static_cast<std::size_t>(counterIt->second) > DATA_NODE_VALUE_MAX)
        {
            counterIt->second = 1;
        }

        retriesLeft--;
    }

    score::mw::log::LogError() << LOG_PREFIX << "getNextNodeIdLocked: Not free nodeId found";
    return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kQuotaExceeded);
}

Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> DataManager::releaseNodeAccessor(
    ClientId clientId,
    DataNodeId nodeId) const
{
    score::mw::log::LogDebug() << LOG_PREFIX << "releaseAccessor for clientId:" << clientId
                               << " with nodeId:" << nodeId;

    const std::lock_guard<std::mutex> lock(m_mutex);

    auto clientItr = m_busy_nodes.find(clientId);
    if (clientItr == m_busy_nodes.end())
    {
        score::mw::log::LogError() << LOG_PREFIX << "releaseAccessor: Failed to get client";
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }
    auto& client = clientItr->second;

    auto nodeItr = client.find(nodeId);
    if (nodeItr == client.end())
    {
        score::mw::log::LogError() << LOG_PREFIX << "releaseAccessor: Failed to get node";
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }
    clientItr->second.erase(nodeId);

    // Remove the whole element if empty
    if (clientItr->second.empty())
    {
        m_busy_nodes.erase(clientItr);
    }

    return {};
}

Expected<DataNodeAccessor<DataNode>, score::crypto::daemon::common::DaemonErrorCode> DataManager::getNodeAccessor(
    ClientId clientId,
    DataNodeId nodeId) const
{
    score::mw::log::LogDebug() << LOG_PREFIX << "getNodeAccessor for clientId:" << clientId
                               << " with nodeId:" << nodeId;

    const std::lock_guard<std::mutex> lock(m_mutex);

    auto nodeRes = getNodeLocked(clientId, nodeId, lock);
    if (!nodeRes.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "getNodeAccessor: Failed to get node";
        return make_unexpected(nodeRes.error());
    }
    auto node = std::move(nodeRes).value();
    if (!node->requiresExclusiveAccess())
    {
        // Non-exclusive, we do not need to keep track of the object,
        // thus no need to capture the manager
        return DataNodeAccessor<DataNode>(std::move(node), nullptr);
    }

    auto clientItr = m_busy_nodes.find(clientId);
    if (clientItr != m_busy_nodes.end())
    {
        auto& client = clientItr->second;
        auto nodeItr = client.find(nodeId);

        if (nodeItr != client.end())
        {
            score::mw::log::LogError() << LOG_PREFIX << "getNodeAccessor: Node is currently busy";
            return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kResourceBusy);
        }
    }

    // Mark busy
    m_busy_nodes.try_emplace(clientId).first->second.insert(nodeId);

    return DataNodeAccessor<DataNode>(std::move(node), this);
}

}  // namespace score::crypto::daemon::data_manager

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

#ifndef CRYPTO_DAEMON_DATA_MANAGER_DATA_MANAGER_HPP_
#define CRYPTO_DAEMON_DATA_MANAGER_DATA_MANAGER_HPP_

#include <cstddef>
#include <memory>
#include <mutex>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <vector>

#include "score/crypto/common/types.hpp"
#include "score/crypto/daemon/common/daemon_error.hpp"
#include "score/crypto/daemon/data_manager/data_node.hpp"
#include "score/crypto/daemon/data_manager/i_data_manager.hpp"

namespace score::crypto::daemon::data_manager
{

/**
 * @brief Thread-safe concrete implementation of IDataManager.
 *
 * Manages hierarchical data nodes with unique identification, combining
 * a client-provided identifier and a manager-assigned per-client counter.
 *
 * @par Internal structure
 *   - Primary index:   @c ClientId → vector of root (entry) node IDs.
 *   - Secondary index: @c ClientId × @c DataNodeId → shared_ptr for O(1) lookup.
 *   - Parent–child relationships are maintained through the DataNode interface.
 *   - Busy-node set tracks nodes currently held by a DataNodeAccessor with exclusive access.
 *
 * @par Thread safety
 *   All public operations are serialised by an internal mutex.
 */
class DataManager : public IDataManager
{
  public:
    DataManager() = default;
    ~DataManager() override = default;

    // Prevent copy/move operations
    DataManager(const DataManager&) = delete;
    DataManager& operator=(const DataManager&) = delete;
    DataManager(DataManager&&) = delete;
    DataManager& operator=(DataManager&&) = delete;

    /// @copydoc IDataManager::addNode
    Expected<DataNodeId, score::crypto::daemon::common::DaemonErrorCode> addNode(
        ClientId clientId,
        std::shared_ptr<DataNode> node) override;

    /// @copydoc IDataManager::addChildNode
    Expected<DataNodeId, score::crypto::daemon::common::DaemonErrorCode>
    addChildNode(ClientId clientId, DataNodeId parentId, std::shared_ptr<DataNode> node) override;

    /// @copydoc IDataManager::addSiblingNode
    Expected<DataNodeId, score::crypto::daemon::common::DaemonErrorCode>
    addSiblingNode(ClientId clientId, DataNodeId siblingId, std::shared_ptr<DataNode> node) override;

    /// @copydoc IDataManager::deleteNode
    Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> deleteNode(ClientId clientId,
                                                                                        DataNodeId nodeId) override;

    /// @copydoc IDataManager::deleteClientNodes
    Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> deleteClientNodes(
        ClientId clientId) override;

    /// @copydoc IDataManager::releaseNodeAccessor
    Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> releaseNodeAccessor(
        ClientId clientId,
        DataNodeId nodeId) const override;

    /// @copydoc IDataManager::getNodeAccessor
    Expected<DataNodeAccessor<DataNode>, score::crypto::daemon::common::DaemonErrorCode> getNodeAccessor(
        ClientId clientId,
        DataNodeId nodeId) const override;

  private:
    /// @brief Mutex serialising all public operations.
    mutable std::mutex m_mutex;

    /// @brief Maps each client to the ordered list of its root (entry) node IDs.
    std::unordered_map<ClientId, std::vector<DataNodeId>> m_entry_nodes_per_client;

    /// @brief Full node storage: ClientId → (DataNodeId → shared_ptr<DataNode>).
    std::unordered_map<ClientId, std::unordered_map<DataNodeId, DataNode::Sptr>> m_node_map;

    /// @brief Monotonically-increasing ID counter per client, wrapping at DATA_NODE_VALUE_MAX.
    std::unordered_map<ClientId, DataNodeId> m_id_counter_per_client;

    /// @brief Tracks nodes that are currently held by an exclusive DataNodeAccessor.
    /// Mutable to allow releaseNodeAccessor() to modify it from const methods.
    mutable std::unordered_map<ClientId, std::unordered_set<DataNodeId>> m_busy_nodes;

    /**
     * @brief Removes @p nodeId from the root-node index of @p clientId.
     *
     * Also removes the entire client entry from the index when the resulting
     * vector becomes empty.
     *
     * @pre The caller must hold @p _lock on @c m_mutex.
     * @param clientId  Owning client identifier.
     * @param nodeId    Root-level node ID to remove.
     * @param _lock     Proof that the caller holds the mutex.
     * @return          @c std::monostate on success, or @c
     * score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument if either @p clientId or @p nodeId is not found.
     */
    Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    removeEntryNodeFromIndex(ClientId clientId, DataNodeId nodeId, const std::lock_guard<std::mutex>& _lock);

    /**
     * @brief Recursively removes @p rootNodeId and all of its descendants from storage.
     *
     * Performs a depth-first traversal, collecting nodes in post-order, then
     * calls removeSingleNodeFromStorage() for each one so that leaf nodes are
     * erased before their ancestors.
     *
     * @pre The caller must hold @p _lock on @c m_mutex.
     * @param clientId    Owning client identifier.
     * @param rootNodeId  Root of the subtree to remove.
     * @param _lock       Proof that the caller holds the mutex.
     * @return            @c std::monostate on success, or the first @c score::crypto::daemon::common::DaemonErrorCode
     * encountered while processing the subtree.
     */
    Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    removeNodesFromStorage(ClientId clientId, DataNodeId rootNodeId, const std::lock_guard<std::mutex>& _lock);

    /**
     * @brief Removes a single node from storage and detaches it from its parent.
     *
     * If the node has a parent, it is removed from the parent's child list via
     * DataNode::removeChild(). If it is a root-level entry node, it is removed
     * from the entry-node index via removeEntryNodeFromIndex(). In both cases the
     * node is then erased from @c m_node_map and @c m_busy_nodes.
     *
     * @pre The caller must hold @p _lock on @c m_mutex.
     * @param node      Shared pointer to the node to remove.
     * @param clientId  Owning client identifier.
     * @param nodeId    @c DataNodeId of the node to remove.
     * @param _lock     Proof that the caller holds the mutex.
     * @return          @c std::monostate on success, or an @c score::crypto::daemon::common::DaemonErrorCode on
     * failure.
     */
    Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> removeSingleNodeFromStorage(
        const std::shared_ptr<DataNode>& node,
        ClientId clientId,
        DataNodeId nodeId,
        const std::lock_guard<std::mutex>& _lock);

    /**
     * @brief Looks up an existing node.
     *
     * @pre The caller must hold @p _lock on @c m_mutex.
     * @param clientId  Owning client identifier.
     * @param nodeId    @c DataNodeId of the node to look up.
     * @param _lock     Proof that the caller holds the mutex.
     * @return          Shared pointer to the node on success, or
     *                  @c score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument if not found.
     */
    Expected<std::shared_ptr<DataNode>, score::crypto::daemon::common::DaemonErrorCode>
    getNodeLocked(ClientId clientId, DataNodeId nodeId, const std::lock_guard<std::mutex>& _lock) const;

    /**
     * @brief Returns the next available @c DataNodeId for the given client.
     *
     * Increments the per-client counter, wrapping at @c DATA_NODE_VALUE_MAX, and
     * retries up to a fixed limit until a free ID (not already present in
     * @c m_node_map) is found.
     *
     * @pre The caller must hold @p _lock on @c m_mutex.
     * @param clientId  Owning client identifier.
     * @param _lock     Proof that the caller holds the mutex.
     * @return          A free @c DataNodeId on success, or
     *                  @c score::crypto::daemon::common::DaemonErrorCode::kQuotaExceeded if no free ID is found within
     *                  the maximum number of retries.
     */
    Expected<DataNodeId, score::crypto::daemon::common::DaemonErrorCode> getNextNodeIdLocked(
        ClientId clientId,
        const std::lock_guard<std::mutex>& _lock);

    /// @brief Limit of nodes per client, used to bound the number of retries in getNextNodeIdLocked().
    const std::size_t m_max_nodes_per_client = 1000;

    /// @brief Log prefix prepended to all diagnostic messages emitted by this class.
    static constexpr std::string_view LOG_PREFIX = "[DATA_MANAGER]";
};

}  // namespace score::crypto::daemon::data_manager

#endif  // CRYPTO_DAEMON_DATA_MANAGER_DATA_MANAGER_HPP_

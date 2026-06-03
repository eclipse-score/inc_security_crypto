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

#ifndef CRYPTO_DAEMON_DATA_MANAGER_I_DATA_MANAGER_HPP_
#define CRYPTO_DAEMON_DATA_MANAGER_I_DATA_MANAGER_HPP_

#include <cstddef>
#include <memory>
#include <variant>

#include "score/crypto/common/types.hpp"
#include "score/crypto/daemon/common/daemon_error.hpp"
#include "score/crypto/daemon/data_manager/data_node.hpp"

namespace score::crypto::daemon::data_manager
{

/// @brief Number of bits in a byte, used for bit-width assertions.
constexpr std::size_t BITS_PER_BYTE = 8;

/// @brief Number of high-order bits in a DataNodeId reserved for future use (bits 56–63).
constexpr std::size_t DATA_NODE_ID_RESERVED_BITS = 8;

/// @brief Number of usable value bits in a DataNodeId (bits 0–55).
constexpr std::size_t DATA_NODE_ID_VALUE_BITS = 56;

static_assert(sizeof(DataNodeId) * BITS_PER_BYTE == DATA_NODE_ID_RESERVED_BITS + DATA_NODE_ID_VALUE_BITS,
              "Error: The size of data_manager::DataNodeId and its components do not match.");

/// @brief Maximum value representable in the 56-bit value field of a DataNodeId.
constexpr std::size_t DATA_NODE_VALUE_MAX = (1ULL << DATA_NODE_ID_VALUE_BITS) - 1;

template <typename T>
class DataNodeAccessor;

/**
 * @brief Generic interface for managing hierarchical data nodes with unique identification.
 *
 * The IDataManager is responsible for:
 *   - Creating data nodes (independent or with parent-child relationships).
 *   - Assigning unique IDs combining a client-provided identifier and a manager-assigned counter.
 *   - Providing exclusive or non-exclusive access to nodes via DataNodeAccessor.
 *   - Deleting nodes and cascading cleanup to all descendants.
 *   - Maintaining hierarchical parent-child relationships.
 *
 * @par Use case
 *   In the crypto daemon, when a connection is established:
 *   - @c ClientId represents the Application ID or Session ID (family identifier).
 *   - Each crypto operation creates data nodes associated with that @c ClientId.
 *   - The manager assigns a unique counter per @c ClientId family.
 *   - When the connection closes, all nodes for that @c ClientId are cleaned up via
 *     deleteClientNodes().
 *
 * @par Thread safety
 *   Derived implementations must document their own thread-safety guarantees.
 */
class IDataManager
{
  public:
    using Sptr = std::shared_ptr<IDataManager>;

    IDataManager() = default;
    IDataManager(const IDataManager&) = delete;
    IDataManager& operator=(const IDataManager&) = delete;
    IDataManager(IDataManager&&) = delete;
    IDataManager& operator=(IDataManager&&) = delete;

    virtual ~IDataManager() = default;

    /**
     * @brief Registers a new root-level node for the given client.
     *
     * The manager assigns a unique @c DataNodeId and stores the node as an entry
     * (top-level) node under @p clientId.
     *
     * @param clientId  Identifier of the owning client.
     * @param node      Shared pointer to the node to register. Must not be null.
     * @return          The assigned @c DataNodeId on success, or an @c score::crypto::daemon::common::DaemonErrorCode
     * on failure.
     */
    virtual Expected<DataNodeId, score::crypto::daemon::common::DaemonErrorCode> addNode(
        ClientId clientId,
        std::shared_ptr<DataNode> node) = 0;

    /**
     * @brief Registers a new child node under an existing parent node.
     *
     * The manager assigns a unique @c DataNodeId, links the new node to @p parentId,
     * and stores it in the node map for @p clientId.
     *
     * @param clientId  Identifier of the owning client.
     * @param parentId  @c DataNodeId of the existing parent node.
     * @param node      Shared pointer to the node to register. Must not be null.
     * @return          The assigned @c DataNodeId on success, or an @c score::crypto::daemon::common::DaemonErrorCode
     * on failure.
     */
    virtual Expected<DataNodeId, score::crypto::daemon::common::DaemonErrorCode>
    addChildNode(ClientId clientId, DataNodeId parentId, std::shared_ptr<DataNode> node) = 0;

    /**
     * @brief Registers a new sibling node under the same parent as an existing node.
     *
     * The manager finds the parent of @p siblingId, assigns a unique @c DataNodeId,
     * links the new node to the same parent, and stores it in the node map for @p clientId.
     *
     * @param clientId  Identifier of the owning client.
     * @param siblingId @c DataNodeId of the existing sibling node whose parent will be used.
     * @param node      Shared pointer to the node to register. Must not be null.
     * @return          The assigned @c DataNodeId on success, or an @c ErrorType on failure
     *                  (including @c ERROR_INVALID_CONTEXT if the sibling has no parent).
     */
    virtual Expected<DataNodeId, score::crypto::daemon::common::DaemonErrorCode>
    addSiblingNode(ClientId clientId, DataNodeId siblingId, std::shared_ptr<DataNode> node) = 0;

    /**
     * @brief Deletes a node and all of its descendants for the given client.
     *
     * Performs a depth-first traversal starting at @p nodeId and removes every
     * node in the subtree from storage and the reference lookup. If the deleted node is a root-level entry
     * node it is also removed from the entry-node index.
     *
     * @param clientId  Identifier of the owning client.
     * @param nodeId    @c DataNodeId of the root node to delete.
     * @return          @c std::monostate on success, or an @c score::crypto::daemon::common::DaemonErrorCode on
     * failure.
     */
    virtual Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> deleteNode(ClientId clientId,
                                                                                                DataNodeId nodeId) = 0;

    /**
     * @brief Deletes all nodes that belong to the given client.
     *
     * Iterates over every root-level entry node registered for @p clientId and
     * recursively removes the whole subtree beneath each one.
     *
     * @param clientId  Identifier of the client whose nodes should be removed.
     * @return          @c std::monostate on success, or an @c score::crypto::daemon::common::DaemonErrorCode if any
     * removal fails. The first encountered error is preserved; remaining nodes are still processed.
     */
    virtual Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> deleteClientNodes(
        ClientId clientId) = 0;

    /**
     * @brief Releases the exclusive-access mark on a node held by a DataNodeAccessor.
     *
     * Called automatically by the DataNodeAccessor destructor. Should not normally
     * be invoked directly by application code.
     *
     * @param clientId  Identifier of the owning client.
     * @param nodeId    @c DataNodeId of the node whose busy mark should be cleared.
     * @return          @c std::monostate on success, or an @c score::crypto::daemon::common::DaemonErrorCode on
     * failure.
     */
    virtual Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> releaseNodeAccessor(
        ClientId clientId,
        DataNodeId nodeId) const = 0;

    /**
     * @brief Obtains a scoped accessor to a node, optionally enforcing exclusive access.
     *
     * If the node requires exclusive access (DataNode::requiresExclusiveAccess() == true),
     * this method marks the node as busy. The busy mark is cleared when the returned
     * DataNodeAccessor is destroyed. Attempting to obtain a second accessor for an
     * exclusively-accessed node while it is busy returns @c
     * score::crypto::daemon::common::DaemonErrorCode::kResourceBusy).
     *
     * @param clientId  Identifier of the owning client.
     * @param nodeId    @c DataNodeId of the node to access.
     * @return          A DataNodeAccessor wrapping the node on success, or an @c
     * score::crypto::daemon::common::DaemonErrorCode on failure (including @c ERROR_RESOURCE_BUSY if already
     * exclusively held).
     */
    virtual Expected<DataNodeAccessor<DataNode>, score::crypto::daemon::common::DaemonErrorCode> getNodeAccessor(
        ClientId clientId,
        DataNodeId nodeId) const = 0;
};

}  // namespace score::crypto::daemon::data_manager

#endif  // CRYPTO_DAEMON_DATA_MANAGER_I_DATA_MANAGER_HPP_

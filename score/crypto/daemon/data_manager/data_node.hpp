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

#ifndef CRYPTO_DAEMON_DATA_MANAGER_DATA_NODE_HPP_
#define CRYPTO_DAEMON_DATA_MANAGER_DATA_NODE_HPP_

#include <atomic>
#include <cstdint>
#include <memory>
#include <string_view>
#include <variant>
#include <vector>

#include "score/crypto/common/types.hpp"

#include "score/crypto/daemon/common/daemon_error.hpp"

namespace score::crypto::daemon::data_manager
{

/// @brief Opaque 64-bit identifier assigned to every DataNode by the DataManager.
using DataNodeId = std::uint64_t;

/// @brief Opaque 64-bit identifier that represents the owning client of a node.
using ClientId = std::uint64_t;

/// @brief Discriminator for concrete DataNode subtypes.
///
/// Provides a MISRA-compliant way to determine a node's logical type
/// before performing a dynamic downcast. Avoids relying on RTTI for
/// branching decisions (MISRA C++ 2023 Rule 11.0.1).
enum class DataNodeType : std::uint8_t
{
    kGeneric = 0U,     ///< Base or unspecialised node
    kConnection = 1U,  ///< IPC connection root node
    kContext = 2U,     ///< Crypto operation context (ContextDataNode)
    kKeySlot = 3U,     ///< Key slot reference (KeySlotDataNode)
    kKeyData = 4U,     ///< Loaded-key reference (KeyDataNode)
};

/**
 * @brief Base class for all concrete data-node implementations.
 *
 * Provides common functionality for managing parent–child relationships,
 * the node identifier, and the owning client identifier.
 * Derived classes are expected to release their own resources in their destructor.
 *
 * @par Ownership model
 *   DataNodes can hold further DataNodes as children, thereby forming tree structures.
 *   Cyclic graphs are not supported and may lead to undefined behaviour.
 *
 * @par Exclusive access
 *   A node constructed with @p exclusiveAccess = @c true (the default) may only be held
 *   by a single DataNodeAccessor at a time. The DataManager enforces this via its
 *   busy-node set. Set @p exclusiveAccess = @c false for nodes that may be accessed
 *   concurrently.
 *
 * @par Thread safety
 *   Parent–child mutation operations require a @c DataNodeManagerToken, which
 *   can only be created by the DataManager. The DataManager serialises all such
 *   calls under its own mutex, so DataNode itself does not carry an internal mutex.
 *   @c getNodeId() and @c getClientId() use atomic loads and are therefore lock-free.
 */

class DataNodeManagerToken;

class DataNode
{
  public:
    using Sptr = std::shared_ptr<DataNode>;

    /**
     * @brief Constructs a node with an uninitialized node ID.
     *
     * The DataManager assigns the definitive @c DataNodeId and @c ClientId
     * via setNodeId() and setClientId() after determining the next available counter value.
     *
     * @param exclusiveAccess  When @c true (default), only one DataNodeAccessor may hold
     *                         this node at a time. Pass @c false for shared access.
     */
    explicit DataNode(bool exclusiveAccess = true);

    virtual ~DataNode() = default;

    /// @brief Returns the logical type of this node.
    ///
    /// Derived classes override to return their specific type tag.
    /// Default implementation returns @c DataNodeType::kGeneric.
    [[nodiscard]] virtual DataNodeType GetNodeType() const noexcept
    {
        return DataNodeType::kGeneric;
    }

    // Prevent copy/move operations
    DataNode(const DataNode&) = delete;
    DataNode& operator=(const DataNode&) = delete;
    DataNode(DataNode&&) = delete;
    DataNode& operator=(DataNode&&) = delete;

    /**
     * @brief Returns the @c DataNodeId assigned by the DataManager.
     * @return Current node identifier (0 if not yet assigned).
     */
    DataNodeId getNodeId() const;

    /**
     * @brief Sets the @c DataNodeId.
     *
     * Only the DataManager may call this method; the required @p token can only be
     * constructed by DataManager (friend relationship).
     *
     * @param nodeId  New node identifier.
     * @param token   Access token proving the caller is the DataManager.
     */
    void setNodeId(DataNodeId nodeId, const DataNodeManagerToken& token);

    /**
     * @brief Returns the @c ClientId of the owning client.
     * @return Current client identifier (0 if not yet assigned).
     */
    ClientId getClientId() const;

    /**
     * @brief Sets the owning @c ClientId.
     *
     * Only the DataManager may call this method; the required @p token can only be
     * constructed by DataManager.
     *
     * @param clientId  New client identifier.
     * @param token     Access token proving the caller is the DataManager.
     */
    void setClientId(ClientId clientId, const DataNodeManagerToken& token);

    /**
     * @brief Sets the parent of this node.
     *
     * Stores a weak pointer to @p parent.
     *
     * @param parent  Weak pointer to the parent node.
     * @param token   Access token proving the caller is the DataManager.
     */
    void setParent(const std::weak_ptr<DataNode>& parent, const DataNodeManagerToken& token);

    /**
     * @brief Returns the @c DataNodeId of the parent node.
     * @param token   Access token proving the caller is the DataManager.
     * @return The parent's @c DataNodeId on success, or @c
     * score::crypto::daemon::common::DaemonErrorCode::kInvalidContext) if this node has no parent (or the parent has
     * already been destroyed).
     */
    Expected<DataNodeId, score::crypto::daemon::common::DaemonErrorCode> getParent(
        const DataNodeManagerToken& token) const;

    /**
     * @brief Appends @p child to the ordered list of this node's children.
     *
     * @param child  Shared pointer to the child node to add.
     * @param token  Access token proving the caller is the DataManager.
     */
    void addChild(const std::shared_ptr<DataNode>& child, const DataNodeManagerToken& token);

    /**
     * @brief Removes the child identified by @p nodeId from this node's child list.
     *
     * @param nodeId  @c DataNodeId of the child to remove.
     * @param token   Access token proving the caller is the DataManager.
     * @return        @c std::monostate on success, or @c
     * score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument if no child with @p nodeId exists.
     */
    Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> removeChild(
        DataNodeId nodeId,
        const DataNodeManagerToken& token);

    /**
     * @brief Returns the @c DataNodeId values of all direct children.
     *
     * The returned vector is a snapshot. Thread safety is guaranteed by the
     * DataManager, which holds its own mutex for the duration of the call.
     *
     * @param token   Access token proving the caller is the DataManager.
     * @return Vector of child node IDs in insertion order.
     */
    std::vector<DataNodeId> getChildren(const DataNodeManagerToken& token) const;

    /**
     * @brief Indicates whether this node requires exclusive access.
     *
     * When @c true, the DataManager allows at most one DataNodeAccessor to hold
     * this node at a time.
     *
     * @return @c true if exclusive access is required; @c false otherwise.
     */
    bool requiresExclusiveAccess() const;

  private:
    /// @brief Manager-assigned unique identifier for this node.
    std::atomic<DataNodeId> m_nodeId = 0;

    /// @brief Identifier of the client that owns this node.
    std::atomic<ClientId> m_client_id = 0;

    /// @brief Weak reference to the parent node (empty for root nodes).
    std::weak_ptr<DataNode> m_parent;

    /// @brief Ordered list of direct child nodes (strong ownership).
    std::vector<std::shared_ptr<DataNode>> m_children;

    /// @brief Whether this node requires exclusive access via DataNodeAccessor.
    const bool m_exclusiveAccess;

    /// @brief Log prefix prepended to all diagnostic messages emitted by this class.
    static constexpr std::string_view LOG_PREFIX = "[DATA_NODE]";
};

}  // namespace score::crypto::daemon::data_manager

#endif  // CRYPTO_DAEMON_DATA_MANAGER_DATA_NODE_HPP_

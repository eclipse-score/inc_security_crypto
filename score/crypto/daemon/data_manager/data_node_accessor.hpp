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

#ifndef CRYPTO_DAEMON_DATA_MANAGER_DATA_NODE_ACCESSOR_HPP_
#define CRYPTO_DAEMON_DATA_MANAGER_DATA_NODE_ACCESSOR_HPP_

#include "score/mw/log/logging.h"

#include <memory>
#include <string_view>
#include <type_traits>

#include "score/crypto/common/types.hpp"
#include "score/crypto/daemon/common/daemon_error.hpp"
#include "score/crypto/daemon/data_manager/data_node.hpp"
#include "score/crypto/daemon/data_manager/i_data_manager.hpp"

namespace score::crypto::daemon::data_manager
{

/**
 * @brief RAII scoped accessor for a DataNode that optionally enforces exclusive access.
 *
 * DataNodeAccessor wraps a shared pointer to a DataNode and keeps a back-pointer
 * to the IDataManager that created it. On destruction the accessor automatically
 * calls IDataManager::releaseNodeAccessor(), clearing the busy mark so that another
 * caller may obtain access to the same node.
 *
 * @par Move semantics
 *   DataNodeAccessor is move-only. The move constructor and move-assignment operator
 *   transfer ownership and null the source's manager pointer, preventing a double
 *   release when the source is destroyed.
 *
 * @par Downcasting
 *   Use the consuming overload downCast<Derived>() to obtain a
 *   @c DataNodeAccessor<Derived> when the concrete type is known. The original
 *   accessor is invalidated by the call.
 *
 * @tparam T  Concrete type of the managed node. Must derive from DataNode.
 */
template <typename T>
class DataNodeAccessor
{
    static_assert(std::is_base_of<DataNode, T>::value, "T must be classes derived from DataNode.");

  public:
    /**
     * @brief Constructs an accessor owning @p node and registered with @p manager.
     *
     * @param node     Shared pointer to the node being accessed.
     * @param manager  Pointer to the IDataManager that will be notified on destruction.
     *                 Pass @c nullptr for non-exclusive nodes.
     */
    DataNodeAccessor(std::shared_ptr<T> node, const IDataManager* manager) : m_node(std::move(node)), m_manager(manager)
    {
    }

    /**
     * @brief Releases the node back to the manager.
     *
     * Calls IDataManager::releaseNodeAccessor() if both the node and manager
     * pointers are valid (i.e. this accessor was not moved-from).
     */
    ~DataNodeAccessor()
    {
        if (m_node && m_manager)
        {
            if (!m_manager->releaseNodeAccessor(m_node->getClientId(), m_node->getNodeId()).has_value())
            {
                score::mw::log::LogError() << LOG_PREFIX << "Failed to release node (" << m_node->getClientId() << ", "
                                           << m_node->getNodeId() << ") in destructor";
            }
        }
    }

    /// @brief Copy construction is disabled; DataNodeAccessor is move-only.
    DataNodeAccessor(const DataNodeAccessor&) = delete;

    /// @brief Copy assignment is disabled; DataNodeAccessor is move-only.
    DataNodeAccessor& operator=(const DataNodeAccessor&) = delete;

    /**
     * @brief Move constructor.
     *
     * Transfers ownership of the node and manager pointer from @p other.
     * After the move, @p other's manager pointer is set to @c nullptr so that its
     * destructor does not release the node.
     *
     * @param other  Source accessor to move from.
     */
    DataNodeAccessor(DataNodeAccessor&& other) noexcept : m_node(std::move(other.m_node)), m_manager(other.m_manager)
    {
        // Explicitly null manager ptr
        other.m_manager = nullptr;
    }

    /**
     * @brief Move assignment operator.
     *
     * Releases the currently held node (if any), then transfers ownership from @p other.
     *
     * @param other  Source accessor to move from.
     */
    DataNodeAccessor& operator=(DataNodeAccessor&& other) noexcept
    {
        if (this == &other)
        {
            return *this;
        }

        if (m_node && m_manager)
        {
            if (!m_manager->releaseNodeAccessor(m_node->getClientId(), m_node->getNodeId()).has_value())
            {
                score::mw::log::LogError() << LOG_PREFIX << "Failed to release node (" << m_node->getClientId() << ", "
                                           << m_node->getNodeId() << ") in move assignment operator";
            }
        }

        m_node = std::move(other.m_node);
        m_manager = other.m_manager;
        // Explicitly null manager ptr
        other.m_manager = nullptr;

        return *this;
    }

    /**
     * @brief Member-access operator (mutable).
     * @return Pointer to the managed node.
     */
    T* operator->()
    {
        return m_node.get();
    }

    /**
     * @brief Dereference operator (mutable).
     * @return Reference to the managed node.
     */
    T& operator*()
    {
        return *m_node;
    }

    /**
     * @brief Member-access operator (const).
     * @return Const pointer to the managed node.
     */
    const T* operator->() const
    {
        return m_node.get();
    }

    /**
     * @brief Dereference operator (const).
     * @return Const reference to the managed node.
     */
    const T& operator*() const
    {
        return *m_node;
    }

    /**
     * @brief Consuming downcast to a more-derived accessor type.
     *
     * Attempts to @c dynamic_pointer_cast the internal node to @c Derived.  On
     * success the current accessor is invalidated (its node and manager pointers
     * are reset) and a new @c DataNodeAccessor<Derived> is returned that takes
     * over responsibility for releasing the node.
     *
     * @tparam Derived  Target type, must derive from @c T.
     * @return          A @c DataNodeAccessor<Derived> on success, or
     *                  @c score::crypto::daemon::common::DaemonErrorCode::kInvalidDataType) if the cast fails.
     */
    template <typename Derived>
    Expected<DataNodeAccessor<Derived>, score::crypto::daemon::common::DaemonErrorCode> downCast() &&
    {
        auto derived = std::dynamic_pointer_cast<Derived>(m_node);
        if (derived == nullptr)
        {
            score::mw::log::LogError() << LOG_PREFIX << "Could not convert to derived type";
            return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidDataType);
        }

        // This downcast is consuming the original object. Thus need to invalidate it.
        m_node.reset();

        const auto* manager = m_manager;
        m_manager = nullptr;

        return DataNodeAccessor<Derived>{std::move(derived), manager};
    }

  private:
    /// @brief Shared pointer to the managed node.
    std::shared_ptr<T> m_node;

    /// @brief Non-owning pointer to the manager; null for non-exclusive nodes or after a move.
    const IDataManager* m_manager;

    /// @brief Log prefix prepended to all diagnostic messages emitted by this class.
    static constexpr std::string_view LOG_PREFIX = "[DATA_NODE_ACCESSOR] ";
};

}  // namespace score::crypto::daemon::data_manager

#endif  // CRYPTO_DAEMON_DATA_MANAGER_DATA_NODE_ACCESSOR_HPP_

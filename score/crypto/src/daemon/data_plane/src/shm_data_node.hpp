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

#ifndef SCORE_CRYPTO_SRC_DAEMON_DATA_PLANE_SHM_DATA_NODE_HPP
#define SCORE_CRYPTO_SRC_DAEMON_DATA_PLANE_SHM_DATA_NODE_HPP

#include "score/crypto/src/api/common/fixed_capacity_string.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/data_manager/data_node.hpp"
#include "score/crypto/src/daemon/data_plane/i_shm_data_node.hpp"
#include "score/crypto/src/daemon/data_plane/i_shm_factory.hpp"
#include "score/crypto/src/daemon/data_plane/i_shm_registry.hpp"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"
#include "score/memory/shared/i_shared_memory_resource.h"
#include <cstdint>
#include <memory>

namespace score::crypto::daemon::data_plane
{

/// @brief DataNode that represents one SHM Object (bulk or pool).
///
/// Owns the OS-level SHM handle (RAII cleanup: UnlinkFilesystemEntry + munmap on destruction).
/// Releases quota by calling registry->Unregister() in destructor.
class ShmDataNode final : public IShmDataNode
{
  public:
    /// @brief Factory method - creates SHM object and registers with quota tracker.
    ///
    /// Generates a unique SHM name from the UID encoded in @p client_id and the current timestamp, then:
    ///
    /// @param registry      Quota tracker (must not be null).
    /// @param factory       SHM factory (must not be null).
    /// @param size          Requested size in bytes.
    /// @param client_id     Owning client (used by the data manager).
    /// @return Shared pointer to created node, or error code.
    static Expected<std::shared_ptr<ShmDataNode>, common::DaemonErrorCode> Create(
        std::shared_ptr<IShmRegistry> registry,
        std::shared_ptr<IShmFactory> factory,
        std::size_t size,
        data_manager::ClientId client_id);

    ~ShmDataNode() override;

    ShmDataNode(const ShmDataNode&) = delete;
    ShmDataNode& operator=(const ShmDataNode&) = delete;
    ShmDataNode(ShmDataNode&&) = delete;
    ShmDataNode& operator=(ShmDataNode&&) = delete;

    // DataNode interface
    [[nodiscard]] data_manager::DataNodeType GetNodeType() const noexcept override
    {
        return data_manager::DataNodeType::kShm;
    }

    // IShmDataNode interface
    [[nodiscard]] std::size_t GetSize() const noexcept override;
    [[nodiscard]] score::crypto::FixedCapacityString<64> GetName() const noexcept override;
    [[nodiscard]] ShmTransportType GetTransportType() const noexcept override;
    [[nodiscard]] score::memory::shared::ISharedMemoryResource* GetHandle() const noexcept override;

  private:
    /// @brief Generate unique SHM name using UID and timestamp.
    static score::crypto::FixedCapacityString<64> GetShmName(std::uint32_t uid);

    /// @brief Private constructor - only callable via Create() factory method.
    ShmDataNode(std::shared_ptr<score::memory::shared::ISharedMemoryResource> handle,
                std::size_t size,
                ShmTransportType transport_type,
                std::weak_ptr<IShmRegistry> registry,
                data_manager::ClientId client_id);

    std::shared_ptr<score::memory::shared::ISharedMemoryResource> m_handle{};
    std::size_t m_size{0U};
    ShmTransportType m_transport_type{ShmTransportType::kPosixNamed};
    std::weak_ptr<IShmRegistry> m_registry{};
    data_manager::ClientId m_client_id{};
};

}  // namespace score::crypto::daemon::data_plane

#endif  // SCORE_CRYPTO_SRC_DAEMON_DATA_PLANE_SHM_DATA_NODE_HPP

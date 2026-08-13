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

#ifndef SCORE_CRYPTO_SRC_DAEMON_DATA_PLANE_I_SHM_DATA_NODE_HPP
#define SCORE_CRYPTO_SRC_DAEMON_DATA_PLANE_I_SHM_DATA_NODE_HPP

#include "score/crypto/src/api/common/fixed_capacity_string.hpp"
#include "score/crypto/src/daemon/data_manager/data_node.hpp"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"
#include "score/memory/shared/i_shared_memory_resource.h"

#include <cstddef>

namespace score::crypto::daemon::data_plane
{

using ShmTransportType = score::crypto::daemon::mediator::operations::ShmTransportType;

/// @brief Interface for SHM data nodes - exposes IPC wire protocol information.
///
/// This interface abstracts SHM node details needed for IPC responses, decoupling
/// the wire protocol from the concrete implementation. It allows the mediator to
/// query SHM metadata without depending on implementation details.
class IShmDataNode : public data_manager::DataNode
{
  public:
    IShmDataNode(const IShmDataNode&) = default;
    IShmDataNode& operator=(const IShmDataNode&) = default;
    IShmDataNode(IShmDataNode&&) noexcept = default;
    IShmDataNode& operator=(IShmDataNode&&) noexcept = default;
    ~IShmDataNode() override = default;

    /// @brief Returns the usable region size in bytes (for IPC response).
    [[nodiscard]] virtual std::size_t GetSize() const noexcept = 0;

    static constexpr std::size_t kMaxNameLength = 64;
    /// @brief Returns the SHM name/path for client-side mapping (for IPC response).
    [[nodiscard]] virtual score::crypto::FixedCapacityString<kMaxNameLength> GetName() const noexcept = 0;

    /// @brief Returns the transport type (kPosixNamed, kPosixTypedMemory, etc).
    [[nodiscard]] virtual ShmTransportType GetTransportType() const noexcept = 0;

    /// @brief Returns the mapped region handle (daemon-side access).
    [[nodiscard]] virtual score::memory::shared::ISharedMemoryResource* GetHandle() const noexcept = 0;

  protected:
    explicit IShmDataNode(bool exclusiveAccess) : DataNode(exclusiveAccess) {}
};

}  // namespace score::crypto::daemon::data_plane

#endif  // SCORE_CRYPTO_SRC_DAEMON_DATA_PLANE_I_SHM_DATA_NODE_HPP

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

#include "score/crypto/src/daemon/data_plane/src/shm_data_node.hpp"

#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/mw/log/logging.h"

#include <chrono>
#include <utility>

namespace
{
constexpr std::string_view LOG_PREFIX = "[SHM_DATA_NODE] ";
}

namespace score::crypto::daemon::data_plane
{

score::crypto::FixedCapacityString<64> ShmDataNode::GetShmName(std::uint32_t uid)
{
    const auto epoch_ns =
        std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
    return score::crypto::FixedCapacityString<64>{std::string("/score_crypto_") + std::to_string(uid) + "_" +
                                                  std::to_string(epoch_ns)};
}

Expected<std::shared_ptr<ShmDataNode>, common::DaemonErrorCode> ShmDataNode::Create(
    std::shared_ptr<IShmRegistry> registry,
    std::shared_ptr<IShmFactory> factory,
    std::size_t size,
    data_manager::ClientId client_id)
{
    const auto uid = control_plane::protocol::GetUidFromClientId(client_id);
    const auto name = GetShmName(uid);

    // 1. Validate inputs
    if (!registry)
    {
        return make_unexpected(common::DaemonErrorCode::kInternalError);
    }
    if (!factory)
    {
        return make_unexpected(common::DaemonErrorCode::kInternalError);
    }

    if (size == 0U)
    {
        score::mw::log::LogError() << ::LOG_PREFIX << "[CREATE_FAILED] size is zero";
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }

    // 2. Register with quota tracker
    auto register_res = registry->Register(uid, size);
    if (!register_res.has_value())
    {
        score::mw::log::LogError() << ::LOG_PREFIX << "[CREATE_FAILED] Register quota failed: "
                                   << static_cast<int>(register_res.error());
        return make_unexpected(register_res.error());
    }

    // 3. Create SHM handle via factory
    auto handle_res = factory->Create(name, uid, size);
    if (!handle_res.has_value())
    {
        score::mw::log::LogError() << ::LOG_PREFIX << "[CREATE_FAILED] factory->Create failed: "
                                   << static_cast<int>(handle_res.error());
        // Rollback quota registration
        registry->Unregister(uid, size);
        return make_unexpected(handle_res.error());
    }

    auto raw = std::move(handle_res).value();
    score::mw::log::LogVerbose() << ::LOG_PREFIX << "[CREATE_SUCCESS] client=" << client_id
                                 << " actual_size=" << raw.size
                                 << " transport=" << static_cast<int>(raw.transport_type);

    // 4. Construct node (private constructor)
    return std::shared_ptr<ShmDataNode>(
        new ShmDataNode(std::move(raw.handle), raw.size, raw.transport_type, registry, client_id));
}

ShmDataNode::ShmDataNode(std::shared_ptr<score::memory::shared::ISharedMemoryResource> handle,
                         std::size_t size,
                         ShmTransportType transport_type,
                         std::weak_ptr<IShmRegistry> registry,
                         data_manager::ClientId client_id)
    : IShmDataNode(/*exclusiveAccess=*/false),
      m_handle(std::move(handle)),
      m_size(size),
      m_transport_type(transport_type),
      m_registry(std::move(registry)),
      m_client_id(client_id)
{
}

ShmDataNode::~ShmDataNode()
{
    score::mw::log::LogVerbose() << ::LOG_PREFIX << "[DESTROY] client=" << m_client_id << " size=" << m_size;

    // 1. Cleanup OS SHM handle
    if (m_handle)
    {
        m_handle->UnlinkFilesystemEntry();  // shm_unlink
        m_handle.reset();                   // munmap
    }

    // 2. Unregister from quota tracker (if registry still alive)
    if (auto registry = m_registry.lock())
    {
        const auto uid = control_plane::protocol::GetUidFromClientId(m_client_id);
        registry->Unregister(uid, m_size);
    }
}

std::size_t ShmDataNode::GetSize() const noexcept
{
    return m_size;
}

score::crypto::FixedCapacityString<64> ShmDataNode::GetName() const noexcept
{
    if (!m_handle)
    {
        return score::crypto::FixedCapacityString<64>{};
    }

    const auto path_opt = m_handle->getPath();
    if (!path_opt)
    {
        return score::crypto::FixedCapacityString<64>{};
    }

    return score::crypto::FixedCapacityString<64>{*path_opt};
}

ShmTransportType ShmDataNode::GetTransportType() const noexcept
{
    return m_transport_type;
}

score::memory::shared::ISharedMemoryResource* ShmDataNode::GetHandle() const noexcept
{
    return m_handle.get();
}

}  // namespace score::crypto::daemon::data_plane

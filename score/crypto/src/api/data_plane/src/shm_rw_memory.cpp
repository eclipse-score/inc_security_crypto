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

#include "score/crypto/src/api/data_plane/src/shm_rw_memory.hpp"

#include "score/crypto/src/api/control_plane/i_connection.hpp"
#include "score/crypto/src/api/data_plane/i_shm_region_registry.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>

namespace score
{

namespace crypto
{

score::Result<IReadWriteMemory::Uptr> ShmReadWriteMemory::Create(
    std::uint64_t node_id,
    std::shared_ptr<void> handle,
    score::cpp::span<uint8_t> region,
    std::weak_ptr<IShmRegionRegistry> registry,
    std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
    DestroyRequestCallback destroy_callback)
{
    if (region.data() == nullptr)
    {
        return score::Result<IReadWriteMemory::Uptr>{
            score::unexpect, MakeError(CryptoErrorCode::kInvalidArgument, "SHM region data is null")};
    }
    if (region.empty())
    {
        return score::Result<IReadWriteMemory::Uptr>{
            score::unexpect, MakeError(CryptoErrorCode::kInvalidArgument, "SHM region size is zero")};
    }

    auto memory = std::make_unique<ShmReadWriteMemory>(MakeUniqueEnabler{},
                                                       node_id,
                                                       std::move(handle),
                                                       region,
                                                       std::move(registry),
                                                       std::move(connection),
                                                       std::move(destroy_callback));
    return memory;
}

ShmReadWriteMemory::ShmReadWriteMemory(MakeUniqueEnabler enabler,
                                       std::uint64_t node_id,
                                       std::shared_ptr<void> handle,
                                       score::cpp::span<uint8_t> region,
                                       std::weak_ptr<IShmRegionRegistry> registry,
                                       std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
                                       DestroyRequestCallback destroy_callback)
    : m_node_id(node_id),
      m_handle(std::move(handle)),
      m_span(region),
      m_registry(std::move(registry)),
      m_connection(std::move(connection)),
      m_destroy_callback(std::move(destroy_callback))
{
    static_cast<void>(enabler);  // suppress unused parameter warning
    if (auto registry = m_registry.lock())
    {
        registry->Register(RegionEntry{node_id, reinterpret_cast<std::uintptr_t>(m_span.data()), m_span.size(), false});
    }
}

ShmReadWriteMemory::~ShmReadWriteMemory()
{
    if (m_span.data() != nullptr)
    {
        // 1. Unregister from client-side registry
        if (auto registry = m_registry.lock())
        {
            registry->Unregister(m_node_id);
        }

        // 2. Send destroy request via injected callback (independent of ShmMemoryFactory).
        // The connection is owned by this object, so the callback stays valid even if the
        // factory that created it has already been destroyed.
        if (m_destroy_callback)
        {
            m_destroy_callback(m_node_id, m_connection);
        }

        m_span = score::cpp::span<uint8_t>{};
    }
}

const uint8_t* ShmReadWriteMemory::data() const noexcept
{
    return m_span.data();
}

std::size_t ShmReadWriteMemory::size() const noexcept
{
    return m_span.size();
}

score::cpp::span<const uint8_t> ShmReadWriteMemory::AsSpan() const noexcept
{
    return m_span;
}

uint8_t* ShmReadWriteMemory::data() noexcept
{
    return m_span.data();
}

score::cpp::span<uint8_t> ShmReadWriteMemory::AsWritableSpan() noexcept
{
    return m_span;
}

score::Result<std::monostate> ShmReadWriteMemory::Resize(std::size_t /* new_size */)
{
    // Resize not supported for shared memory in POC.
    // Would require daemon coordination to ftruncate + re-mmap.
    return score::MakeUnexpected(CryptoErrorCode::kUnsupportedOperation);
}

std::uint64_t ShmReadWriteMemory::GetNodeId() const noexcept
{
    return m_node_id;
}

}  // namespace crypto

}  // namespace score

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

#ifndef SCORE_CRYPTO_API_DATA_PLANE_SRC_SHM_RW_MEMORY_HPP
#define SCORE_CRYPTO_API_DATA_PLANE_SRC_SHM_RW_MEMORY_HPP

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/common/i_memory.hpp"
#include "score/crypto/src/api/data_plane/i_shm_region_registry.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <variant>

namespace score::crypto::api::control_plane
{
class IConnection;
}

namespace score
{

namespace crypto
{

/// @brief Callback function type for sending SHM_DESTROY_OBJECT to daemon.
///
/// This callback is invoked when a ShmReadWriteMemory is destroyed, allowing
/// the destruction logic to be injected independently of ShmMemoryFactory.
/// The callback is stateless: it receives the node_id of the memory region being
/// destroyed together with the connection owned by ShmReadWriteMemory,
/// so it does not depend on the factory outliving the memory object.
using DestroyRequestCallback =
    std::function<void(std::uint64_t, std::shared_ptr<score::crypto::api::control_plane::IConnection>)>;

/// @brief Client-side shared memory backed by POSIX shm.
///
/// RAII: the destructor unmaps the region and unregisters from the registry (if still available).
/// The registry is held as weak_ptr to handle the case where the registry is destroyed before
/// this memory object.
class ShmReadWriteMemory final : public IReadWriteMemory
{
  public:
    /// @brief Helper tag type to allow std::make_unique to access the private constructor.
    struct MakeUniqueEnabler
    {
    };

    /// @brief Factory method to create a valid ShmReadWriteMemory instance.
    ///
    /// Returns an error if the provided region is empty or has a null base address.
    /// @param node_id           DataManager node ID assigned by daemon.
    /// @param handle            Opaque handle owning the mapping lifetime (custom deleter triggers unmap).
    /// @param region            Usable memory region (excluding control block).
    /// @param registry          Weak reference to the SHM region registry for unregistration on destruction.
    /// @param connection        Connection used by the destroy callback to send SHM_DESTROY_OBJECT. Owned here so the
    /// callback does not depend on the factory outliving this object. May be null (no destroy request is sent).
    /// @param destroy_callback  Callback to send SHM_DESTROY_OBJECT on destruction. If null/empty, no destroy request
    /// is sent.
    /// @return A unique_ptr to the created memory object, or a CryptoErrorCode on invalid input.
    static score::Result<IReadWriteMemory::Uptr> Create(
        std::uint64_t node_id,
        std::shared_ptr<void> handle,
        score::cpp::span<uint8_t> region,
        std::weak_ptr<IShmRegionRegistry> registry,
        std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
        DestroyRequestCallback destroy_callback);

    /// @brief Tag-dispatching constructor used internally by Create().
    ShmReadWriteMemory(MakeUniqueEnabler,
                       std::uint64_t node_id,
                       std::shared_ptr<void> handle,
                       score::cpp::span<uint8_t> region,
                       std::weak_ptr<IShmRegionRegistry> registry,
                       std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
                       DestroyRequestCallback destroy_callback);

    ~ShmReadWriteMemory() override;

    // IReadOnlyMemory
    const uint8_t* data() const noexcept override;
    std::size_t size() const noexcept override;
    score::cpp::span<const uint8_t> AsSpan() const noexcept override;

    // IReadWriteMemory
    uint8_t* data() noexcept override;
    score::cpp::span<uint8_t> AsWritableSpan() noexcept override;
    score::Result<std::monostate> Resize(std::size_t new_size) override;

    /// @brief Returns the daemon-assigned node ID.
    std::uint64_t GetNodeId() const noexcept;

  private:
    std::uint64_t m_node_id;
    std::shared_ptr<void> m_handle;
    score::cpp::span<uint8_t> m_span{};
    std::weak_ptr<IShmRegionRegistry> m_registry;
    std::shared_ptr<score::crypto::api::control_plane::IConnection> m_connection;
    DestroyRequestCallback m_destroy_callback;
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_API_DATA_PLANE_SRC_SHM_RW_MEMORY_HPP

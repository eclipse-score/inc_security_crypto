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

#ifndef SCORE_CRYPTO_API_DATA_PLANE_SRC_SHM_MEMORY_ALLOCATOR_HPP
#define SCORE_CRYPTO_API_DATA_PLANE_SRC_SHM_MEMORY_ALLOCATOR_HPP

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/common/i_memory.hpp"
#include "score/crypto/src/api/common/i_memory_allocator.hpp"
#include "score/crypto/src/api/control_plane/i_connection.hpp"
#include "score/crypto/src/api/data_plane/i_read_write_memory_factory.hpp"
#include "score/crypto/src/api/data_plane/i_shm_region_registry.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/result/result.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>

namespace score
{

namespace crypto
{

/// @brief Client-side shared memory allocator implementing IMemoryAllocator.
class ShmMemoryAllocator final : public IMemoryAllocator
{
  private:
    /// @brief Tag type to restrict constructor access to Create method only.
    struct ConstructorTag
    {
        explicit ConstructorTag() = default;
    };

  public:
    /// @brief Factory method to create a ShmMemoryAllocator instance.
    /// @param connection  Connection to the daemon for IPC requests. Must not be null.
    /// @param factory     Factory that opens, registers, and returns IReadWriteMemory. Must not be null.
    /// @param registry    Shared registry — used for quota/usage queries. Must not be null.
    /// @return std::unique_ptr<ShmMemoryAllocator> on success, or CryptoErrorCode::kInvalidArgument if any parameter is
    /// null.
    static score::Result<std::unique_ptr<ShmMemoryAllocator>> Create(
        std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
        IReadWriteMemoryFactory::Sptr factory,
        std::shared_ptr<IShmRegionRegistry> registry);

    /// @brief Constructor with tag - only callable via Create method.
    /// @param tag         Tag to restrict construction to Create method.
    /// @param connection  Connection to the daemon for IPC requests. Must not be null (validated by Create).
    /// @param factory     Factory that opens, registers, and returns IReadWriteMemory. Must not be null (validated by
    /// Create).
    /// @param registry    Shared registry — used for quota/usage queries. Must not be null (validated by Create).
    explicit ShmMemoryAllocator(ConstructorTag tag,
                                std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
                                IReadWriteMemoryFactory::Sptr factory,
                                std::shared_ptr<IShmRegionRegistry> registry);

    ~ShmMemoryAllocator() override = default;

    ShmMemoryAllocator(const ShmMemoryAllocator&) = delete;
    ShmMemoryAllocator& operator=(const ShmMemoryAllocator&) = delete;
    ShmMemoryAllocator(ShmMemoryAllocator&&) = default;
    ShmMemoryAllocator& operator=(ShmMemoryAllocator&&) = default;

    // IMemoryAllocator
    score::Result<IReadWriteMemory::Uptr> Allocate(std::size_t size,
                                                   std::optional<ProviderType> provider_type = std::nullopt) override;
    score::Result<IReadWriteMemory::Uptr> Allocate(std::size_t size, const CryptoResourceId& provider) override;

    std::size_t GetQuota() const noexcept override;
    std::size_t GetCurrentUsage() const noexcept override;

  private:
    score::crypto::Expected<IReadWriteMemory::Uptr, CryptoErrorCode> AllocateInternal(
        std::size_t size,
        std::optional<ProviderType> provider_type,
        std::optional<std::uint16_t> provider_id);

    // Shared pointers for lifetime management (validated non-null by Create)
    std::shared_ptr<score::crypto::api::control_plane::IConnection> m_connection_ptr;
    IReadWriteMemoryFactory::Sptr m_factory_ptr;
    std::shared_ptr<IShmRegionRegistry> m_registry_ptr;
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_API_DATA_PLANE_SRC_SHM_MEMORY_ALLOCATOR_HPP

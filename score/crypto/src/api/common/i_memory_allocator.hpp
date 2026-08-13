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

#ifndef SCORE_CRYPTO_SRC_API_COMMON_I_MEMORY_ALLOCATOR_HPP
#define SCORE_CRYPTO_SRC_API_COMMON_I_MEMORY_ALLOCATOR_HPP

#include "score/crypto/src/api/common/i_memory.hpp"
#include "score/crypto/src/api/common/types.hpp"
#include "score/result/result.h"

#include <cstddef>
#include <memory>
#include <optional>

namespace score
{

namespace crypto
{

/// @brief Memory allocator interface for the data plane.
///
/// The daemon enforces per-application quotas. Allocation may fail if the
/// quota is exceeded or the requested memory type is not available.
///
/// @see dec_rec__crypto__memory_allocator_separation for the rationale
///      behind separating this interface from ICryptoStack.
// TODO: What would be the initial values on the allocated memory? Zeroed out by default? Uninitialized? This should be
// documented and consistent across implementations.
// TODO: Should there be a choice for the user to decide on the allocation behavior (e.g., zero-initialized vs.
// uninitialized) to allow for performance optimizations when zeroing is not needed?
class IMemoryAllocator
{
  public:
    using Uptr = std::unique_ptr<IMemoryAllocator>;

    virtual ~IMemoryAllocator() = default;

    IMemoryAllocator(const IMemoryAllocator&) = delete;
    IMemoryAllocator& operator=(const IMemoryAllocator&) = delete;
    IMemoryAllocator(IMemoryAllocator&&) = default;
    IMemoryAllocator& operator=(IMemoryAllocator&&) = default;

    /// @brief Allocates shared memory, optionally targeting a specific provider type.
    /// @param size          Number of bytes to allocate.
    /// @param provider_type Optional provider-category hint. std::nullopt selects the default shared memory
    /// implementation.
    /// @return Writable memory object on success, error on failure.
    /// @note The allocated memory is not initialized.
    virtual score::Result<IReadWriteMemory::Uptr> Allocate(
        std::size_t size,
        std::optional<ProviderType> provider_type = std::nullopt) = 0;

    /// @brief Allocates shared memory compatible with a specific resolved provider instance.
    /// @param size     Number of bytes to allocate.
    /// @param provider Resolved resource handle identifying the target provider.
    /// @return Writable memory object on success, error on failure.
    /// @note The allocated memory is not initialized.
    virtual score::Result<IReadWriteMemory::Uptr> Allocate(std::size_t size, const CryptoResourceId& provider) = 0;

    /// @brief Returns the maximum allocation permitted for this application.
    /// @return Quota in bytes (daemon-configured, overridable per app)
    virtual std::size_t GetQuota() const noexcept = 0;

    /// @brief Returns the currently allocated bytes for this application.
    virtual std::size_t GetCurrentUsage() const noexcept = 0;

  protected:
    IMemoryAllocator() = default;
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_SRC_API_COMMON_I_MEMORY_ALLOCATOR_HPP

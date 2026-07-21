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

#ifndef SCORE_MW_CRYPTO_API_COMMON_I_MEMORY_ALLOCATOR_HPP
#define SCORE_MW_CRYPTO_API_COMMON_I_MEMORY_ALLOCATOR_HPP

#include "score/mw/crypto/api/common/i_memory_region.hpp"
#include "score/mw/crypto/api/common/types.hpp"
#include "score/result/result.h"

#include <cstddef>
#include <memory>

namespace score
{
namespace mw
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

    /// @brief Allocates shared memory with kDefault type.
    /// @param size Number of bytes to allocate
    /// @return Writable memory region on success, error on failure
    /// @note Daemon tracks this against per-application quota.
    virtual score::Result<IReadWriteMemoryRegion::Uptr> Allocate(std::size_t size) = 0;

    /// @brief Allocates provider-compatible shared memory.
    /// @param size Number of bytes to allocate
    /// @param type Memory type (kDefault or kProviderCompatible)
    /// @param provider Resolved provider handle for provider-compatible allocation
    /// @return Writable memory region on success, error on failure
    /// @note Enables zero-copy path from application to crypto device when
    ///       kProviderCompatible is used with the correct provider.
    virtual score::Result<IReadWriteMemoryRegion::Uptr> Allocate(std::size_t size,
                                                                 MemoryType type,
                                                                 const CryptoResourceId& provider) = 0;

    /// @brief Returns the maximum allocation permitted for this application.
    /// @return Quota in bytes (daemon-configured, overridable per app)
    virtual std::size_t GetQuota() const noexcept = 0;

    /// @brief Returns the currently allocated bytes for this application.
    virtual std::size_t GetCurrentUsage() const noexcept = 0;

  protected:
    IMemoryAllocator() = default;
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_COMMON_I_MEMORY_ALLOCATOR_HPP

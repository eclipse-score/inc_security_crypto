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

#ifndef SCORE_CRYPTO_API_COMMON_I_MEMORY_HPP
#define SCORE_CRYPTO_API_COMMON_I_MEMORY_HPP

#include "score/result/result.h"
#include "score/span.hpp"

#include <cstdint>
#include <memory>

namespace score
{

namespace crypto
{

/// @brief Immutable view into an allocated shared memory (data plane).
///
/// Represents a read-only window into shared memory managed by the daemon.
/// Used as input to all operation contexts. The underlying memory is shared
/// between the library and daemon, avoiding copies across the IPC boundary.
///
/// Destruction releases the shared memory segment back to the daemon's pool
/// and decrements the per-application quota.
class IReadOnlyMemory
{
  public:
    using Uptr = std::unique_ptr<IReadOnlyMemory>;

    virtual ~IReadOnlyMemory() = default;

    IReadOnlyMemory(const IReadOnlyMemory&) = delete;
    IReadOnlyMemory& operator=(const IReadOnlyMemory&) = delete;
    IReadOnlyMemory(IReadOnlyMemory&&) = default;
    IReadOnlyMemory& operator=(IReadOnlyMemory&&) = default;

    /// @brief Returns a pointer to the beginning of the shared memory.
    virtual const uint8_t* data() const noexcept = 0;

    /// @brief Returns the size of the shared memory in bytes.
    virtual std::size_t size() const noexcept = 0;

    /// @brief Returns an immutable span over the shared memory.
    /// @note Convenience wrapper: equivalent to span{data(), size()}.
    virtual score::cpp::span<const uint8_t> AsSpan() const noexcept = 0;

  protected:
    IReadOnlyMemory() = default;
};

/// @brief Mutable view into an allocated shared memory (data plane).
///
/// Extends IReadOnlyMemory with write access. Used for both writing
/// input data into shared memory and receiving output from operations.
/// The underlying memory is shared between library and daemon.
///
/// Destruction releases the shared memory segment back to the daemon's pool
/// and decrements the per-application quota.
class IReadWriteMemory : public IReadOnlyMemory
{
  public:
    using Uptr = std::unique_ptr<IReadWriteMemory>;

    ~IReadWriteMemory() override = default;

    IReadWriteMemory(const IReadWriteMemory&) = delete;
    IReadWriteMemory& operator=(const IReadWriteMemory&) = delete;
    IReadWriteMemory(IReadWriteMemory&&) = default;
    IReadWriteMemory& operator=(IReadWriteMemory&&) = default;

    /// @brief Returns a const pointer to the beginning of the shared memory.
    virtual const uint8_t* data() const noexcept = 0;

    /// @brief Returns a mutable pointer to the beginning of the shared memory.
    virtual uint8_t* data() noexcept = 0;

    /// @brief Returns a mutable span over the shared memory.
    virtual score::cpp::span<uint8_t> AsWritableSpan() noexcept = 0;

    /// @brief Resizes the shared memory.
    /// @param new_size The desired size in bytes
    /// @return std::monostate on success, error if the new size exceeds quota or is invalid
    /// @note May invalidate previously obtained pointers/spans.
    virtual score::Result<std::monostate> Resize(std::size_t new_size) = 0;

  protected:
    IReadWriteMemory() = default;
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_API_COMMON_I_MEMORY_HPP

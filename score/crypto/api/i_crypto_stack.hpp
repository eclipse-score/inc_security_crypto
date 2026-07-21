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

#ifndef SCORE_MW_CRYPTO_API_I_CRYPTO_STACK_HPP
#define SCORE_MW_CRYPTO_API_I_CRYPTO_STACK_HPP

#include "score/mw/crypto/api/common/i_memory_allocator.hpp"
#include "score/mw/crypto/api/i_crypto_context.hpp"
#include "score/result/result.h"

#include <memory>

namespace score
{
namespace mw
{
namespace crypto
{

/// @brief Application-level entry point for cryptographic operations.
///
/// The underlying daemon connection is managed internally and shared
/// across all ICryptoStack instances within the same process. All objects
/// obtained via this interface — contexts, allocators, and resource guards
/// — have independent lifetimes and may safely outlive this instance.
class ICryptoStack
{
  public:
    using Uptr = std::unique_ptr<ICryptoStack>;

    virtual ~ICryptoStack() = default;

    ICryptoStack(const ICryptoStack&) = delete;
    ICryptoStack& operator=(const ICryptoStack&) = delete;
    ICryptoStack(ICryptoStack&&) = default;
    ICryptoStack& operator=(ICryptoStack&&) = default;

    /// @brief Creates a new crypto context for resource resolution and operations.
    /// @return Unique pointer to the created context
    /// @note Multiple contexts can be created from one stack for parallel
    ///       independent operation streams.
    virtual score::Result<ICryptoContext::Uptr> CreateCryptoContext() = 0;

    /// @brief Returns the data-plane memory allocator.
    /// @return Result containing ownership of the memory allocator.
    ///         On success, extract via `.value()`. On error, check `.error()`.
    /// @note Allocated memory regions remain valid until explicitly destroyed
    ///       or the allocator is destroyed.
    virtual score::Result<IMemoryAllocator::Uptr> GetMemoryAllocator() = 0;

    // FUTURE: Uncomment
    /// @brief Returns the secure storage manager.
    /// @return Result containing ownership of the secure storage manager.
    ///         On success, extract via `.value()`. On error, check `.error()`.
    /// @note Provides application-level AEAD-encrypted blob storage backed by
    ///       the crypto daemon's key hierarchy.
    // virtual score::Result<ISecureStorageManager::Uptr> GetSecureStorageManager() = 0;

  protected:
    ICryptoStack() = default;
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_I_CRYPTO_STACK_HPP

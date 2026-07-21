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

#ifndef SCORE_MW_CRYPTO_API_CONTEXTS_I_RANDOM_CONTEXT_HPP
#define SCORE_MW_CRYPTO_API_CONTEXTS_I_RANDOM_CONTEXT_HPP

#include "score/mw/crypto/api/contexts/i_context.hpp"
#include "score/result/result.h"
#include "score/span.hpp"

#include <cstddef>
#include <cstdint>

namespace score
{
namespace mw
{
namespace crypto
{

/// @brief Interface for random number generation.
///
/// Non-streaming context — provides direct Generate() and Seed() operations.
/// The RNG source is bound at context creation via RandomContextConfig
/// (algorithm and optional provider).
///
/// Suitable for generating IVs, nonces, key material, and other
/// cryptographic random data. For PQC key generation (e.g., ML-KEM),
/// the RNG is used internally by the key generation operation.
class IRandomContext : public IContext
{
  public:
    using Uptr = std::unique_ptr<IRandomContext>;

    ~IRandomContext() override = default;

    IRandomContext(const IRandomContext&) = delete;
    IRandomContext& operator=(const IRandomContext&) = delete;
    IRandomContext(IRandomContext&&) = default;
    IRandomContext& operator=(IRandomContext&&) = default;

    /// @brief Generates cryptographically secure random bytes.
    /// @param output Buffer to fill with random data
    /// @return Number of bytes generated on success, error on failure
    virtual score::Result<std::size_t> Generate(score::cpp::span<uint8_t> output) = 0;

    /// @brief Seeds the random number generator with additional entropy.
    /// @param seed Entropy data to mix into the RNG state
    /// @return std::monostate on success, error on failure
    /// @note Not all providers support explicit seeding. Some hardware RNGs
    ///       may ignore this call (returning success without action).
    virtual score::Result<std::monostate> Seed(score::cpp::span<const uint8_t> seed) = 0;

  protected:
    IRandomContext() = default;
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_CONTEXTS_I_RANDOM_CONTEXT_HPP

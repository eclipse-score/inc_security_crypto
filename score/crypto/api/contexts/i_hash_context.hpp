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

#ifndef SCORE_MW_CRYPTO_API_CONTEXTS_I_HASH_CONTEXT_HPP
#define SCORE_MW_CRYPTO_API_CONTEXTS_I_HASH_CONTEXT_HPP

#include "score/mw/crypto/api/contexts/i_streaming_output_context.hpp"
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

/// @brief Interface for hash/digest operations.
///
/// Exposes Init, Update, Reset, and Finalize from base classes plus
/// hash-specific SingleShot() and GetDigestSize().
/// Init() is exposed with the base default (iv = std::nullopt);
/// hash implementations reject a non-null IV.
///
/// Compatible with classical algorithms (SHA-256, SHA-3) and PQC hash-based
/// schemes (e.g., XMSS/LMS hash functions, SHAKE for ML-DSA).
class IHashContext : public IStreamingOutputContext
{
  public:
    using Uptr = std::unique_ptr<IHashContext>;

    virtual ~IHashContext() = default;

    IHashContext(const IHashContext&) = delete;
    IHashContext& operator=(const IHashContext&) = delete;
    IHashContext(IHashContext&&) = default;
    IHashContext& operator=(IHashContext&&) = default;

    // -- Streaming API (from base classes) --
    using IStreamingContext::Init;
    using IStreamingContext::Reset;
    using IStreamingContext::Update;
    using IStreamingOutputContext::Finalize;

    /// @brief Computes the hash digest in a single call.
    /// @param input Data to hash
    /// @param output Buffer to receive the digest
    /// @return Number of bytes written on success, error on failure
    /// @note Equivalent to Init() + Update(input) + Finalize(output).
    virtual score::Result<std::size_t> SingleShot(score::cpp::span<const uint8_t> input,
                                                  score::cpp::span<uint8_t> output) = 0;

    /// @brief Returns the digest size in bytes for the configured algorithm.
    /// @note For variable-output hash functions (e.g., SHAKE), returns the
    ///       default output length configured at context creation.
    virtual std::size_t GetDigestSize() const noexcept = 0;

  protected:
    IHashContext() = default;
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_CONTEXTS_I_HASH_CONTEXT_HPP

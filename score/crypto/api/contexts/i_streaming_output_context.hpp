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

#ifndef SCORE_MW_CRYPTO_API_CONTEXTS_I_STREAMING_OUTPUT_CONTEXT_HPP
#define SCORE_MW_CRYPTO_API_CONTEXTS_I_STREAMING_OUTPUT_CONTEXT_HPP

#include "score/mw/crypto/api/contexts/i_streaming_context.hpp"
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

/// @brief Base interface for streaming operations that produce output (Init → Update* → Finalize).
///
/// Extends IStreamingContext with protected Finalize() and GetOutputSize()
/// methods. Derived context interfaces selectively expose these in their
/// public sections via using-declarations.
///
/// Used as base for: IHashContext, IMacContext, ICipherContext, ISignContext.
class IStreamingOutputContext : public IStreamingContext
{
  public:
    using Uptr = std::unique_ptr<IStreamingOutputContext>;

    virtual ~IStreamingOutputContext() = default;

    IStreamingOutputContext(const IStreamingOutputContext&) = delete;
    IStreamingOutputContext& operator=(const IStreamingOutputContext&) = delete;
    IStreamingOutputContext(IStreamingOutputContext&&) = default;
    IStreamingOutputContext& operator=(IStreamingOutputContext&&) = default;

  protected:
    IStreamingOutputContext() = default;

    /// @brief Finalizes the streaming operation and writes the result.
    /// @param output Buffer to receive the output data
    /// @return Number of bytes written on success, error on failure
    /// @note After calling Finalize(), Init() must be called again before
    ///       starting a new operation.
    virtual score::Result<std::size_t> Finalize(score::cpp::span<uint8_t> output) = 0;

    /// @brief Returns the expected output size in bytes.
    /// @note For hash, this is the digest size. For encrypt/decrypt, this depends
    ///       on the algorithm and the amount of data processed. Call after Init()
    ///       for meaningful results.
    virtual std::size_t GetOutputSize() const noexcept = 0;
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_CONTEXTS_I_STREAMING_OUTPUT_CONTEXT_HPP

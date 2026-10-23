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

#ifndef SCORE_CRYPTO_SRC_API_CONTEXTS_I_MAC_CONTEXT_HPP
#define SCORE_CRYPTO_SRC_API_CONTEXTS_I_MAC_CONTEXT_HPP

#include "score/crypto/src/api/contexts/i_streaming_context.hpp"
#include "score/result/result.h"
#include "score/span.hpp"

#include <cstddef>
#include <cstdint>

namespace score
{

namespace crypto
{

/// @brief Interface for message authentication code (MAC) operations.
///
/// Exposes Init() and Reset() from the base class and adds Update(),
/// Finalize(), Verify() and GetMacSize().
/// Init() uses the optional-IV base signature; passing a value enables
/// algorithms like GMAC, while std::nullopt (the default) is used for
/// HMAC/CMAC.
///
/// Compatible with HMAC-SHA256, CMAC-AES, GMAC, and other MAC algorithms.
class IMacContext : public IStreamingContext
{
  public:
    using Uptr = std::unique_ptr<IMacContext>;

    ~IMacContext() override = default;

    IMacContext(const IMacContext&) = delete;
    IMacContext& operator=(const IMacContext&) = delete;
    IMacContext(IMacContext&&) = default;
    IMacContext& operator=(IMacContext&&) = default;

    // -- Streaming API (from base class) --
    using IStreamingContext::Init;
    using IStreamingContext::Reset;

    /// @brief Feeds a chunk of input data into the operation.
    /// @return std::monostate on success, error on failure
    /// @note Can be called multiple times after Init().
    virtual score::Result<std::monostate> Update(score::cpp::span<const uint8_t> data) = 0;

    /// @brief Finalizes the MAC computation and writes the tag.
    /// @param output Buffer to receive the MAC, at least GetMacSize() bytes
    /// @return Number of bytes written on success, error on failure
    /// @note After Finalize(), Init() must be called again before the next Update().
    virtual score::Result<std::size_t> Finalize(score::cpp::span<uint8_t> output) = 0;

    /// @brief Verifies a MAC against the accumulated data.
    /// @param mac The MAC value to verify
    /// @return true if MAC is valid, false if invalid, error on failure
    /// @note Must be called after Update() calls. Alternative to Finalize()
    ///       when you want to verify rather than produce a MAC.
    virtual score::Result<bool> Verify(score::cpp::span<const uint8_t> mac) = 0;

    /// @brief Returns the MAC size in bytes for the configured algorithm.
    virtual std::size_t GetMacSize() const noexcept = 0;

  protected:
    IMacContext() = default;
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_SRC_API_CONTEXTS_I_MAC_CONTEXT_HPP

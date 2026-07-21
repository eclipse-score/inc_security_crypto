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

#ifndef SCORE_MW_CRYPTO_API_CONTEXTS_I_MAC_CONTEXT_HPP
#define SCORE_MW_CRYPTO_API_CONTEXTS_I_MAC_CONTEXT_HPP

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

/// @brief Interface for message authentication code (MAC) operations.
///
/// Exposes Init, Update, Reset, and Finalize from base classes plus
/// MAC-specific Verify() and GetMacSize().
/// Init() uses the optional-IV base signature; passing a value enables
/// algorithms like GMAC, while std::nullopt (the default) is used for
/// HMAC/CMAC.
///
/// Compatible with HMAC-SHA256, CMAC-AES, GMAC, and other MAC algorithms.
class IMacContext : public IStreamingOutputContext
{
  public:
    using Uptr = std::unique_ptr<IMacContext>;

    ~IMacContext() override = default;

    IMacContext(const IMacContext&) = delete;
    IMacContext& operator=(const IMacContext&) = delete;
    IMacContext(IMacContext&&) = default;
    IMacContext& operator=(IMacContext&&) = default;

    // -- Streaming API (from base classes) --
    using IStreamingContext::Init;
    using IStreamingContext::Reset;
    using IStreamingContext::Update;
    using IStreamingOutputContext::Finalize;

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
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_CONTEXTS_I_MAC_CONTEXT_HPP

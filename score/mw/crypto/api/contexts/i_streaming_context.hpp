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

#ifndef SCORE_MW_CRYPTO_API_CONTEXTS_I_STREAMING_CONTEXT_HPP
#define SCORE_MW_CRYPTO_API_CONTEXTS_I_STREAMING_CONTEXT_HPP

#include "score/mw/crypto/api/contexts/i_context.hpp"
#include "score/result/result.h"
#include "score/span.hpp"

#include <cstdint>
#include <optional>

namespace score
{
namespace mw
{
namespace crypto
{

/// @brief Base interface for streaming crypto operations (Init → Update* pattern).
///
/// Provides the common Init(), Update(), and Reset() methods as protected
/// virtual functions. Derived context interfaces (IHashContext, IMacContext,
/// ICipherContext, etc.) selectively expose these in their public sections
/// via using-declarations, so that each context presents a self-contained
/// API surface to the user.
///
/// Init() accepts an optional initialization vector to support algorithms
/// that require one (e.g. GMAC, AES-CBC). Contexts that do not use an IV
/// simply call Init() with the default std::nullopt.
class IStreamingContext : public IContext
{
  public:
    using Uptr = std::unique_ptr<IStreamingContext>;

    virtual ~IStreamingContext() = default;

    IStreamingContext(const IStreamingContext&) = delete;
    IStreamingContext& operator=(const IStreamingContext&) = delete;
    IStreamingContext(IStreamingContext&&) = default;
    IStreamingContext& operator=(IStreamingContext&&) = default;

  protected:
    IStreamingContext() = default;

    /// @brief Initializes the streaming operation.
    /// @param iv Optional initialization vector. Derived contexts expose this
    ///           selectively: hash/sign contexts default to std::nullopt,
    ///           MAC contexts accept an optional IV (e.g. GMAC), and
    ///           cipher/AEAD contexts require a mandatory IV via their own
    ///           public Init(span) signature.
    /// @return std::monostate on success, error if context is in an invalid state
    /// @note Must be called before Update(). Calling Init() on an already-active
    ///       stream resets the context for a new operation.
    virtual score::Result<std::monostate> Init(std::optional<score::cpp::span<const uint8_t>> iv = std::nullopt) = 0;

    /// @brief Feeds data into the streaming operation.
    /// @param data Input data chunk
    /// @return std::monostate on success, error if Init() was not called
    /// @note Can be called multiple times after Init().
    virtual score::Result<std::monostate> Update(score::cpp::span<const uint8_t> data) = 0;

    /// @brief Resets the context to its post-construction state for reuse.
    ///
    /// After a streaming sequence completes (Finalize / SignFinalize /
    /// VerifyFinalize / VerifyAndFinalize) or when a sequence is aborted
    /// mid-stream, Reset() returns the context to its initial state —
    /// equivalent to when it was first obtained from the factory.
    ///
    /// The key binding, algorithm, and configuration established at context
    /// creation are **preserved** — only the streaming state machine and
    /// any accumulated intermediate data are cleared.  This avoids the
    /// factory + IPC round-trip cost of creating a new context.
    ///
    /// Typical reuse cycle:
    ///   Init() → Update()* → Finalize() → Reset() → Init() → ...
    ///
    /// @return std::monostate on success; error if the context is in a state that
    ///         cannot be reset (e.g., already destroyed) or if the daemon
    ///         fails to clear internal state.
    ///
    /// @post  The context is in the same state as immediately after factory
    ///        creation.  Init() must be called before the next Update().
    ///
    /// @note  Calling Reset() on an already-idle (post-construction or
    ///        post-Reset) context is a no-op that returns success.
    /// @note  An IPC call to the daemon is required so that provider-side
    ///        resources (e.g., OpenSSL EVP_MD_CTX) are also cleared.
    virtual score::Result<std::monostate> Reset() = 0;
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_CONTEXTS_I_STREAMING_CONTEXT_HPP

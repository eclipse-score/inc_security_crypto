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

#ifndef SCORE_MW_CRYPTO_API_CONTEXTS_I_AEAD_CONTEXT_HPP
#define SCORE_MW_CRYPTO_API_CONTEXTS_I_AEAD_CONTEXT_HPP

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

/// @brief Interface for authenticated encryption with associated data (AEAD).
///
/// Unified context — direction (encrypt/decrypt) is set via AeadContextConfig.
/// Supports streaming: Init(iv) → UpdateAad* → Update* → Finalize/VerifyAndFinalize.
///
/// Exposes Init() and Reset() from the base class. Init() uses the base
/// optional-IV signature; a nonce/IV must be provided — passing nullopt
/// returns kUnsupportedOperation. Update() and Finalize() use AEAD-specific
/// signatures with separate tag output.
///
/// Compatible with AES-GCM, AES-CCM, ChaCha20-Poly1305, and future
/// PQC-hybrid AEAD constructions.
///
/// @note Derives from IStreamingContext (not IStreamingOutputContext) because
///       AEAD has dual finalization paths (Finalize for encrypt, VerifyAndFinalize
///       for decrypt) with different semantics.
class IAeadContext : public IStreamingContext
{
  public:
    using Uptr = std::unique_ptr<IAeadContext>;

    ~IAeadContext() override = default;

    IAeadContext(const IAeadContext&) = delete;
    IAeadContext& operator=(const IAeadContext&) = delete;
    IAeadContext(IAeadContext&&) = default;
    IAeadContext& operator=(IAeadContext&&) = default;

    // -- Streaming API (from base classes) --
    using IStreamingContext::Init;
    using IStreamingContext::Reset;

    /// @brief Feeds additional authenticated data (AAD).
    /// @param aad Associated data to authenticate (not encrypted)
    /// @return std::monostate on success, error on failure
    /// @note Must be called after Init() and before Update(). Can be called
    ///       multiple times. All AAD must be fed before any plaintext/ciphertext.
    virtual score::Result<std::monostate> UpdateAad(score::cpp::span<const uint8_t> aad) = 0;

    /// @brief Processes input data (plaintext or ciphertext depending on direction).
    /// @param input Input data to encrypt or decrypt
    /// @param output Output buffer for the result
    /// @return Number of output bytes written on success, error on failure
    virtual score::Result<std::size_t> Update(score::cpp::span<const uint8_t> input,
                                              score::cpp::span<uint8_t> output) = 0;

    /// @brief Finalizes encryption, producing remaining output and the auth tag.
    /// @param output Buffer for any remaining ciphertext
    /// @param tag_out Buffer to receive the authentication tag
    /// @return Number of remaining output bytes written on success, error on failure
    /// @note Only valid in encrypt mode (CipherDirection::kEncrypt in config).
    virtual score::Result<std::size_t> Finalize(score::cpp::span<uint8_t> output,
                                                score::cpp::span<uint8_t> tag_out) = 0;

    /// @brief Finalizes decryption, verifying the authentication tag.
    /// @param output Buffer for any remaining plaintext
    /// @param tag_in The authentication tag to verify
    /// @return true if tag verification succeeds, error on failure or tag mismatch
    /// @note Only valid in decrypt mode (CipherDirection::kDecrypt in config).
    ///       If verification fails, no plaintext is produced (output is wiped).
    virtual score::Result<bool> VerifyAndFinalize(score::cpp::span<uint8_t> output,
                                                  score::cpp::span<const uint8_t> tag_in) = 0;

    /// @brief Returns the authentication tag size in bytes for the configured algorithm.
    virtual std::size_t GetTagSize() const noexcept = 0;

  protected:
    IAeadContext() = default;
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_CONTEXTS_I_AEAD_CONTEXT_HPP

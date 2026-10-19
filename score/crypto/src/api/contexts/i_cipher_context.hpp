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

#ifndef SCORE_CRYPTO_SRC_API_CONTEXTS_I_CIPHER_CONTEXT_HPP
#define SCORE_CRYPTO_SRC_API_CONTEXTS_I_CIPHER_CONTEXT_HPP

#include "score/crypto/src/api/contexts/i_streaming_context.hpp"
#include "score/result/result.h"
#include "score/span.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>

namespace score
{

namespace crypto
{

/// @brief Unified interface for symmetric cipher operations (encryption and decryption).
///
/// The direction (encrypt or decrypt) is selected via CipherContextConfig::SetDirection()
/// at context creation time. Supports streaming (Init → Update → Finalize) and
/// single-shot modes. The key and algorithm are bound at context creation via
/// CipherContextConfig.
///
/// Exposes Init() and Reset() from the base class and adds Update(), Finalize(),
/// SingleShot() and GetMaximumOutputSize().
/// Init() uses the base optional-IV signature; for IV-based modes (AES-CBC,
/// AES-CTR, ChaCha20) an IV must be provided — passing nullopt returns
/// kUnsupportedOperation. For ECB mode (no IV), pass std::nullopt.
///
/// Output buffers are sized with GetMaximumOutputSize(); a buffer of that size
/// is always accepted.
///
/// Compatible with classical ciphers (AES-CBC, AES-CTR, AES-ECB, ChaCha20)
/// and PQC key-encapsulation based hybrid encryption schemes.
///
/// @par Example — encryption (streaming, CBC)
/// @code
///   CipherContextConfig cfg;
///   cfg.SetAlgorithm("AES-256-CBC")
///      .SetKey(key_slot)
///      .SetDirection(CipherDirection::kEncrypt);
///   auto cipher = ctx->CreateCipherContext(cfg).value();
///   std::vector<uint8_t> out(cipher->GetMaximumOutputSize(plaintext.size()).value());
///   cipher->Init(iv);   // span implicitly converts to optional<span>
///   auto n = cipher->Update(plaintext, out).value();
///   auto m = cipher->Finalize(score::cpp::span<uint8_t>{out}.subspan(n)).value();
/// @endcode
///
/// @par Example — decryption (single-shot)
/// @code
///   CipherContextConfig cfg;
///   cfg.SetAlgorithm("AES-256-CBC")
///      .SetKey(key_slot)
///      .SetDirection(CipherDirection::kDecrypt);
///   auto cipher = ctx->CreateCipherContext(cfg).value();
///   auto n = cipher->SingleShot(iv, ciphertext, plaintext_buf).value();
/// @endcode
class ICipherContext : public IStreamingContext
{
  public:
    using Uptr = std::unique_ptr<ICipherContext>;

    ~ICipherContext() override = default;

    ICipherContext(const ICipherContext&) = delete;
    ICipherContext& operator=(const ICipherContext&) = delete;
    ICipherContext(ICipherContext&&) = default;
    ICipherContext& operator=(ICipherContext&&) = default;

    // -- Streaming API (from base class) --
    using IStreamingContext::Init;
    using IStreamingContext::Reset;

    /// @brief Processes a chunk of input data and writes output.
    ///
    /// When configured for encryption: input is plaintext, output is ciphertext.
    /// When configured for decryption: input is ciphertext, output is plaintext.
    ///
    /// @param input Input data to encrypt or decrypt
    /// @param output Output buffer for the result, at least
    ///               GetMaximumOutputSize(input.size()) bytes
    /// @return Number of output bytes written on success, error on failure.
    ///         Buffered bytes (an incomplete block, or the last block when
    ///         decrypting with padding) are written by a later Update() or
    ///         Finalize(), so the count can differ from input.size() in either
    ///         direction.
    /// @note Can be called multiple times after Init() for streaming operation.
    virtual score::Result<std::size_t> Update(score::cpp::span<const uint8_t> input,
                                              score::cpp::span<uint8_t> output) = 0;

    /// @brief Finishes the stream and writes the trailing bytes.
    /// @param output Buffer for the trailing bytes; GetMaximumOutputSize(0) bytes
    ///               always suffice, and a stream mode writes none.
    /// @return Number of output bytes written on success, error on failure
    /// @note After Finalize(), Init() must be called again before the next Update().
    virtual score::Result<std::size_t> Finalize(score::cpp::span<uint8_t> output) = 0;

    /// @brief Processes data in a single call (Init + Update* + Finalize combined).
    ///
    /// When configured for encryption: input is plaintext, output is ciphertext.
    /// When configured for decryption: input is ciphertext, output is plaintext.
    ///
    /// @param iv Initialization vector / nonce, absent for IV-less modes such as
    ///           ECB. Mirrors Init(), which takes the same optional.
    /// @param input Input data to encrypt or decrypt
    /// @param output Output buffer for the result, at least
    ///               GetMaximumOutputSize(input.size()) bytes
    /// @return Number of output bytes written on success, error on failure
    virtual score::Result<std::size_t> SingleShot(std::optional<score::cpp::span<const uint8_t>> iv,
                                                  score::cpp::span<const uint8_t> input,
                                                  score::cpp::span<uint8_t> output) = 0;

    /// @brief Returns the output buffer size that any single call accepts for a given input.
    ///
    /// The bound covers Update() and SingleShot() for an input of input_size
    /// bytes, and Finalize() for input_size = 0. It is input_size plus one
    /// cipher block (one byte for a stream mode such as CTR).
    ///
    /// @param input_size Length of the input passed to the call being sized
    /// @return Maximum number of bytes the call writes, error if the daemon
    ///         query fails or the bound overflows std::size_t
    virtual score::Result<std::size_t> GetMaximumOutputSize(std::size_t input_size) const = 0;

  protected:
    ICipherContext() = default;
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_SRC_API_CONTEXTS_I_CIPHER_CONTEXT_HPP

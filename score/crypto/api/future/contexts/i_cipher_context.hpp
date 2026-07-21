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

#ifndef SCORE_MW_CRYPTO_API_CONTEXTS_I_CIPHER_CONTEXT_HPP
#define SCORE_MW_CRYPTO_API_CONTEXTS_I_CIPHER_CONTEXT_HPP

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

/// @brief Unified interface for symmetric cipher operations (encryption and decryption).
///
/// The direction (encrypt or decrypt) is selected via CipherContextConfig::SetDirection()
/// at context creation time. Supports streaming (Init → Update → Finalize) and
/// single-shot modes. The key and algorithm are bound at context creation via
/// CipherContextConfig.
///
/// Exposes Init(), Reset(), Finalize(), and GetOutputSize() from base classes.
/// Init() uses the base optional-IV signature; for IV-based modes (AES-CBC,
/// AES-CTR, ChaCha20) an IV must be provided — passing nullopt returns
/// kUnsupportedOperation. For ECB mode (no IV), pass std::nullopt.
/// Update() uses the cipher-specific (input, output) signature.
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
///   cipher->Init(iv);   // span implicitly converts to optional<span>
///   auto n = cipher->Update(plaintext, ciphertext_buf).value();
///   auto m = cipher->Finalize(final_buf).value();
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
class ICipherContext : public IStreamingOutputContext
{
  public:
    using Uptr = std::unique_ptr<ICipherContext>;

    ~ICipherContext() override = default;

    ICipherContext(const ICipherContext&) = delete;
    ICipherContext& operator=(const ICipherContext&) = delete;
    ICipherContext(ICipherContext&&) = default;
    ICipherContext& operator=(ICipherContext&&) = default;

    // -- Streaming API (from base classes) --
    using IStreamingContext::Init;
    using IStreamingContext::Reset;
    using IStreamingOutputContext::Finalize;
    using IStreamingOutputContext::GetOutputSize;

    /// @brief Processes a chunk of input data and writes output.
    ///
    /// When configured for encryption: input is plaintext, output is ciphertext.
    /// When configured for decryption: input is ciphertext, output is plaintext.
    ///
    /// @param input Input data to encrypt or decrypt
    /// @param output Output buffer for the result
    /// @return Number of output bytes written on success, error on failure
    /// @note Can be called multiple times after Init() for streaming operation.
    virtual score::Result<std::size_t> Update(score::cpp::span<const uint8_t> input,
                                              score::cpp::span<uint8_t> output) = 0;

    /// @brief Processes data in a single call (Init + Update* + Finalize combined).
    ///
    /// When configured for encryption: input is plaintext, output is ciphertext.
    /// When configured for decryption: input is ciphertext, output is plaintext.
    ///
    /// @param iv Initialization vector / nonce
    /// @param input Input data to encrypt or decrypt
    /// @param output Output buffer for the result
    /// @return Number of output bytes written on success, error on failure
    virtual score::Result<std::size_t> SingleShot(score::cpp::span<const uint8_t> iv,
                                                  score::cpp::span<const uint8_t> input,
                                                  score::cpp::span<uint8_t> output) = 0;

  protected:
    ICipherContext() = default;
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_CONTEXTS_I_CIPHER_CONTEXT_HPP

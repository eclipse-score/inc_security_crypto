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

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/contexts/i_streaming_output_context.hpp"
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
/// Exposes Init(), Reset(), Finalize(), and GetOutputSize() from base classes.
/// Init() uses the base optional-IV signature; for IV-based modes (AES-CBC,
/// AES-CTR, ChaCha20) an IV must be provided — passing nullopt returns
/// kUnsupportedOperation. For ECB mode (no IV), pass std::nullopt.
/// Update() uses the cipher-specific (input, output) signature.
///
/// Output sizing: for a cipher, GetOutputSize() returns the block size (1 for
/// a stream mode), not the size of any one result. An Update() output buffer
/// must hold input.size() + block size, because a buffered partial block may be
/// flushed ahead of the current chunk; Finalize() writes at most one block; a
/// SingleShot() output buffer must hold input.size() + block size.
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
/// @note Every cipher Update produces output, so the output-less
///       IStreamingContext::Update(span) cannot be honoured. It is sealed here
///       and is not among the using-declarations below; Update(input, output) is
///       the streaming entry point for a cipher.
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

  protected:
    /// @brief Refuses the output-less streaming signature inherited from
    ///        IStreamingContext.
    ///
    /// Sealed so that no cipher implementation has to restate the refusal, and
    /// none can give this overload a meaning. Not reachable through
    /// ICipherContext: it stays protected and carries no using-declaration.
    score::Result<std::monostate> Update(score::cpp::span<const uint8_t> /*data*/) final
    {
        return score::Result<std::monostate>{
            score::unexpect,
            MakeError(CryptoErrorCode::kUnsupportedOperation, "Cipher Update requires an output buffer")};
    }

  public:
    /// @brief Processes data in a single call (Init + Update* + Finalize combined).
    ///
    /// When configured for encryption: input is plaintext, output is ciphertext.
    /// When configured for decryption: input is ciphertext, output is plaintext.
    ///
    /// @param iv Initialization vector / nonce, absent for IV-less modes such as
    ///           ECB. Mirrors Init(), which takes the same optional.
    /// @param input Input data to encrypt or decrypt
    /// @param output Output buffer for the result
    /// @return Number of output bytes written on success, error on failure
    virtual score::Result<std::size_t> SingleShot(std::optional<score::cpp::span<const uint8_t>> iv,
                                                  score::cpp::span<const uint8_t> input,
                                                  score::cpp::span<uint8_t> output) = 0;

  protected:
    ICipherContext() = default;
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_SRC_API_CONTEXTS_I_CIPHER_CONTEXT_HPP

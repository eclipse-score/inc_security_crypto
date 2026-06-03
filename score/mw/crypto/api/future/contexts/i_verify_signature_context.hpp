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

#ifndef SCORE_MW_CRYPTO_API_CONTEXTS_I_VERIFY_SIGNATURE_CONTEXT_HPP
#define SCORE_MW_CRYPTO_API_CONTEXTS_I_VERIFY_SIGNATURE_CONTEXT_HPP

#include "score/mw/crypto/api/contexts/i_streaming_context.hpp"
#include "score/result/result.h"
#include "score/span.hpp"

#include <cstdint>

namespace score
{
namespace mw
{
namespace crypto
{

/// @brief Interface for digital signature verification.
///
/// Exposes Init(), Update(), and Reset() from base classes for streaming
/// message feeding. Adds VerifyFinalize() for signature checking and
/// SingleShot() for convenience.
///
/// Compatible with classical (ECDSA, RSA-PSS, EdDSA) and PQC verification
/// algorithms (ML-DSA, SLH-DSA, XMSS, LMS).
///
/// @note Does NOT inherit from IStreamingOutputContext since verification
///       produces a boolean result, not output bytes.
class IVerifySignatureContext : public IStreamingContext
{
  public:
    using Uptr = std::unique_ptr<IVerifySignatureContext>;

    ~IVerifySignatureContext() override = default;

    IVerifySignatureContext(const IVerifySignatureContext&) = delete;
    IVerifySignatureContext& operator=(const IVerifySignatureContext&) = delete;
    IVerifySignatureContext(IVerifySignatureContext&&) = default;
    IVerifySignatureContext& operator=(IVerifySignatureContext&&) = default;

    // -- Streaming API (from base classes) --
    using IStreamingContext::Init;
    using IStreamingContext::Reset;
    using IStreamingContext::Update;

    /// @brief Finalizes verification and checks the signature.
    /// @param signature The signature to verify against the accumulated data
    /// @return true if signature is valid, false if invalid, error on failure
    virtual score::Result<bool> VerifyFinalize(score::cpp::span<const uint8_t> signature) = 0;

    /// @brief Verifies a signature in a single call.
    /// @param data The signed data
    /// @param signature The signature to verify
    /// @return true if signature is valid, false if invalid, error on failure
    virtual score::Result<bool> SingleShot(score::cpp::span<const uint8_t> data,
                                           score::cpp::span<const uint8_t> signature) = 0;

  protected:
    IVerifySignatureContext() = default;
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_CONTEXTS_I_VERIFY_SIGNATURE_CONTEXT_HPP

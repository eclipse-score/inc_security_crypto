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

#ifndef SCORE_MW_CRYPTO_API_CONTEXTS_I_SIGN_CONTEXT_HPP
#define SCORE_MW_CRYPTO_API_CONTEXTS_I_SIGN_CONTEXT_HPP

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

/// @brief Interface for digital signature generation.
///
/// Exposes Init(), Update(), and Reset() from base classes for streaming
/// message feeding. Adds SignFinalize() for signature production,
/// SingleShot() for convenience, and GetSignatureSize() for buffer sizing.
///
/// Compatible with classical algorithms (ECDSA, RSA-PSS, EdDSA) and
/// PQC signature schemes (ML-DSA / Dilithium, SLH-DSA / SPHINCS+,
/// XMSS, LMS). PQC algorithms are specified via AlgorithmId string
/// (e.g., "ML-DSA-65", "SLH-DSA-SHA2-128s").
class ISignContext : public IStreamingOutputContext
{
  public:
    using Uptr = std::unique_ptr<ISignContext>;

    ~ISignContext() override = default;

    ISignContext(const ISignContext&) = delete;
    ISignContext& operator=(const ISignContext&) = delete;
    ISignContext(ISignContext&&) = default;
    ISignContext& operator=(ISignContext&&) = default;

    // -- Streaming API (from base classes) --
    using IStreamingContext::Init;
    using IStreamingContext::Reset;
    using IStreamingContext::Update;

    /// @brief Finalizes the signing operation and produces the signature.
    /// @param signature Output buffer for the signature
    /// @return Number of signature bytes written on success, error on failure
    /// @note For PQC schemes like ML-DSA, signature sizes may be larger than
    ///       classical algorithms. Use GetSignatureSize() to pre-allocate.
    virtual score::Result<std::size_t> SignFinalize(score::cpp::span<uint8_t> signature) = 0;

    /// @brief Signs data in a single call.
    /// @param data Input data to sign
    /// @param signature Output buffer for the signature
    /// @return Number of signature bytes written on success, error on failure
    virtual score::Result<std::size_t> SingleShot(score::cpp::span<const uint8_t> data,
                                                  score::cpp::span<uint8_t> signature) = 0;

    /// @brief Returns the expected signature size in bytes.
    /// @note For PQC algorithms, this returns the fixed signature size specified
    ///       by the algorithm parameter set (e.g., 3293 bytes for ML-DSA-65).
    virtual std::size_t GetSignatureSize() const noexcept = 0;

  protected:
    ISignContext() = default;
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_CONTEXTS_I_SIGN_CONTEXT_HPP

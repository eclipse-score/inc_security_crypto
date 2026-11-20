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

/// @file pqc_provider_verify_handler.hpp
/// @brief PQC Provider implementation of the verification handler.

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_PQC_PROVIDER_VERIFY_HANDLER_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_PQC_PROVIDER_VERIFY_HANDLER_HPP

#include "score/crypto/src/daemon/provider/score_provider/operations/verify/score_verify_handler.hpp"
#include "score/pqc_provider/include/pqc_provider_ffi.h"

namespace score::crypto::daemon::provider::score_provider::pqc_provider
{

class PqcProviderKeyHandler;

/// @brief PQC Provider implementation of the provider-neutral verification handler.
///
/// Supports ML-DSA signature verification through the PQC Provider backend.
/// The handler binds a non-owning key handler and performs single-shot
/// verification.
class PqcProviderVerifyHandler final : public operations::verify::ScoreVerifyHandler
{
  public:
    /// @brief Create an PQC Provider verification handler.
    ///
    /// Takes ownership of the operation executor and stores the selected ML-DSA
    /// algorithm.
    ///
    /// @param executor Provider-neutral executor for verification operations.
    /// @param algorithm Resolved ML-DSA algorithm descriptor.
    PqcProviderVerifyHandler(std::unique_ptr<operations::verify::VerifyExecutor> executor,
                            const AlgorithmDescriptor& algorithm);
    ~PqcProviderVerifyHandler() override = default;

    PqcProviderVerifyHandler(const PqcProviderVerifyHandler&) = delete;
    PqcProviderVerifyHandler& operator=(const PqcProviderVerifyHandler&) = delete;
    PqcProviderVerifyHandler(const PqcProviderVerifyHandler&&) = delete;
    PqcProviderVerifyHandler& operator=(const PqcProviderVerifyHandler&&) = delete;

    /// @brief Return whether this handler supports the resolved signature algorithm.
    [[nodiscard]] static bool IsAlgorithmSupported(const AlgorithmDescriptor& algorithm) noexcept;

    /// @brief Validate the algorithm and bind the verification key.
    ///
    /// The bound key must contain public or private signature material for the
    /// configured algorithm and have a valid native handle or imported public key.
    ///
    /// @param init_params Context initialization parameters containing the
    ///                    bound verification key.
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> InitializeContext(
        const handler::InitializationParams& init_params) override;
    /// @brief Verify a complete message and signature in a single operation.
    ///
    /// Returns true for a valid signature, false for an invalid signature, and
    /// an error for invalid input, missing keys, or backend failures.
    ///
    /// @param data Message to verify.
    /// @param signature Signature to verify against the message.
    [[nodiscard]] Expected<bool, common::DaemonErrorCode> SingleShotVerify(
        score::cpp::span<const std::uint8_t> data,
        score::cpp::span<const std::uint8_t> signature) override;

    /// @brief Return the ML-DSA signature size, or zero for an unsupported algorithm.
    [[nodiscard]] std::size_t GetSignatureSize() const noexcept override;

  private:
    /// @brief Validate that the configured algorithm is a supported ML-DSA algorithm.
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> ValidateAlgorithm() const;
    const PqcProviderKeyHandler* m_key{nullptr};  ///< Non-owning pointer to the bound key handler.
};
}  // namespace score::crypto::daemon::provider::score_provider::pqc_provider

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_PQC_PROVIDER_VERIFY_HANDLER_HPP

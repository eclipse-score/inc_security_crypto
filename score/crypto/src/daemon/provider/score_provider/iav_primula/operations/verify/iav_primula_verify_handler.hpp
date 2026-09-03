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

/// @file iav_primula_verify_handler.hpp
/// @brief IAV-Primula implementation of the verification handler.

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_IAV_PRIMULA_VERIFY_HANDLER_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_IAV_PRIMULA_VERIFY_HANDLER_HPP

#include "score/crypto/src/daemon/provider/score_provider/operations/verify/score_verify_handler.hpp"
#include "score/iav_primula/include/iav_primula_ffi.h"

namespace score::crypto::daemon::provider::score_provider::iav_primula
{

/// @brief IAV-Primula implementation of the provider-neutral verification handler.
///
/// Supports ML-DSA signature verification through the IAV-Primula backend.
/// The handler binds a non-owning native key handle and performs single-shot
/// verification.
class IavPrimulaVerifyHandler final : public operations::verify::ScoreVerifyHandler
{
  public:
    /// @brief Create an IAV-Primula verification handler.
    ///
    /// Takes ownership of the operation executor and stores the selected ML-DSA
    /// algorithm.
    ///
    /// @param executor Provider-neutral executor for verification operations.
    /// @param algorithm ML-DSA algorithm identifier.
    IavPrimulaVerifyHandler(std::unique_ptr<operations::verify::VerifyExecutor> executor,
                            common::AlgorithmId algorithm);
    ~IavPrimulaVerifyHandler() override = default;

    IavPrimulaVerifyHandler(const IavPrimulaVerifyHandler&) = delete;
    IavPrimulaVerifyHandler& operator=(const IavPrimulaVerifyHandler&) = delete;
    IavPrimulaVerifyHandler(const IavPrimulaVerifyHandler&&) = delete;
    IavPrimulaVerifyHandler& operator=(const IavPrimulaVerifyHandler&&) = delete;

    /// @brief Validate the algorithm and bind the verification key.
    ///
    /// The bound key must be an IAV-Primula key with a valid native handle.
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
        const common::RequestParameter& data,
        const common::RequestParameter& signature) override;

  private:
    /// @brief Validate that the configured algorithm is a supported ML-DSA algorithm.
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> ValidateAlgorithm() const;
    iav_primula_key_handle* m_key{nullptr};  ///< Non-owning handle borrowed from the bound key handler.
};
}  // namespace score::crypto::daemon::provider::score_provider::iav_primula

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_IAV_PRIMULA_VERIFY_HANDLER_HPP

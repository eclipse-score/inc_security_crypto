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

/// @file iav_primula_sign_handler.hpp
/// @brief IAV-Primula implementation of the signature handler.

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_IAV_PRIMULA_SIGN_HANDLER_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_IAV_PRIMULA_SIGN_HANDLER_HPP

#include "score/crypto/src/daemon/provider/score_provider/operations/sign/score_sign_handler.hpp"
#include "score/iav_primula/include/iav_primula_ffi.h"

namespace score::crypto::daemon::provider::score_provider::iav_primula
{

/// @brief IAV-Primula implementation of the provider-neutral signature handler.
///
/// Supports ML-DSA signing through the IAV-Primula backend. The handler binds
/// a non-owning native key handle and manages the output buffer for
/// single-shot signatures.
class IavPrimulaSignHandler final : public operations::sign::ScoreSignHandler
{
  public:
    /// @brief Create an IAV-Primula signature handler.
    ///
    /// Takes ownership of the operation executor and stores the selected ML-DSA
    /// algorithm.
    ///
    /// @param executor Provider-neutral executor for signature operations.
    /// @param algorithm ML-DSA algorithm identifier.
    IavPrimulaSignHandler(std::unique_ptr<operations::sign::SignExecutor> executor, common::AlgorithmId algorithm);

    ~IavPrimulaSignHandler() override = default;

    IavPrimulaSignHandler(const IavPrimulaSignHandler&) = delete;
    IavPrimulaSignHandler& operator=(const IavPrimulaSignHandler&) = delete;
    IavPrimulaSignHandler(IavPrimulaSignHandler&&) = delete;
    IavPrimulaSignHandler& operator=(IavPrimulaSignHandler&&) = delete;

    /// @brief Validate the algorithm and bind the signing key.
    ///
    /// The bound key must be an IAV-Primula key with a valid native handle.
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> InitializeContext(
        const ::score::crypto::daemon::provider::handler::InitializationParams& init_params) override;
    /// @brief Clear the internal output buffer and reset the handler state.
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> Reset() override;
    /// @brief Sign a complete message in a single operation.
    ///
    /// If output is not provided, the handler allocates an owning response
    /// buffer. Otherwise, the caller-provided output buffer is used.
    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> SingleShotSign(
        const common::RequestParameter& data,
        std::optional<common::RequestParameter> output) override;
    /// @brief Return the fixed signature size for the configured ML-DSA algorithm.
    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> GetSignatureSize() const override;

  private:
    /// @brief Validate that the configured algorithm is a supported ML-DSA algorithm.
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> ValidateAlgorithm() const;
    /// @brief Return the expected signature size for the configured algorithm.
    [[nodiscard]] std::size_t GetExpectedSignatureSize() const noexcept;

    iav_primula_key_handle* m_key{nullptr};    ///< Non-owning handle borrowed from the bound key handler.
    std::vector<std::uint8_t> m_outputBuffer;  ///< Internally owned single-shot signature buffer.
};

}  // namespace score::crypto::daemon::provider::score_provider::iav_primula

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_IAV_PRIMULA_SIGN_HANDLER_HPP

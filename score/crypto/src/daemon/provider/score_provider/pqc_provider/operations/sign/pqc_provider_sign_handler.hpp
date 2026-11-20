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

/// @file pqc_provider_sign_handler.hpp
/// @brief PQC Provider implementation of the signature handler.

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_PQC_PROVIDER_SIGN_HANDLER_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_PQC_PROVIDER_SIGN_HANDLER_HPP

#include "score/crypto/src/daemon/provider/score_provider/operations/sign/score_sign_handler.hpp"
#include "score/pqc_provider/include/pqc_provider_ffi.h"

namespace score::crypto::daemon::provider::score_provider::pqc_provider
{

/// @brief PQC Provider implementation of the provider-neutral signature handler.
///
/// Supports ML-DSA signing through the PQC Provider backend. The handler binds
/// a non-owning native key handle and writes single-shot signatures into
/// caller-provided buffers.
class PqcProviderSignHandler final : public operations::sign::ScoreSignHandler
{
  public:
    /// @brief Create an PQC Provider signature handler.
    ///
    /// Takes ownership of the operation executor and stores the selected ML-DSA
    /// algorithm.
    ///
    /// @param executor Provider-neutral executor for signature operations.
    /// @param algorithm Resolved ML-DSA algorithm descriptor.
    PqcProviderSignHandler(std::unique_ptr<operations::sign::SignExecutor> executor, const AlgorithmDescriptor& algorithm);

    ~PqcProviderSignHandler() override = default;

    PqcProviderSignHandler(const PqcProviderSignHandler&) = delete;
    PqcProviderSignHandler& operator=(const PqcProviderSignHandler&) = delete;
    PqcProviderSignHandler(PqcProviderSignHandler&&) = delete;
    PqcProviderSignHandler& operator=(PqcProviderSignHandler&&) = delete;

    /// @brief Return whether this handler supports the resolved signature algorithm.
    [[nodiscard]] static bool IsAlgorithmSupported(const AlgorithmDescriptor& algorithm) noexcept;

    /// @brief Validate the algorithm and bind the signing key.
    ///
    /// The bound key must contain private signature material for the configured
    /// algorithm and have a valid native handle.
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> InitializeContext(
        const ::score::crypto::daemon::provider::handler::InitializationParams& init_params) override;
    /// @brief Sign a complete message in a single operation.
    ///
    /// Writes into the caller-provided buffer and returns the number of bytes written.
    [[nodiscard]] Expected<std::size_t, common::DaemonErrorCode> SingleShotSign(
        score::cpp::span<const std::uint8_t> data,
        score::cpp::span<std::uint8_t> signature) override;
    /// @brief Return the ML-DSA signature size, or zero for an unsupported algorithm.
    [[nodiscard]] std::size_t GetSignatureSize() const noexcept override;

  private:
    /// @brief Validate that the configured algorithm is a supported ML-DSA algorithm.
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> ValidateAlgorithm() const;

    pqc_provider_key_handle* m_key{nullptr};    ///< Non-owning handle borrowed from the bound key handler.
};

}  // namespace score::crypto::daemon::provider::score_provider::pqc_provider

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_PQC_PROVIDER_SIGN_HANDLER_HPP

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

/// @file iav_primula_kem_handler.hpp
/// @brief IAV-Primula implementation of the KEM handler.

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_IAV_PRIMULA_KEM_HANDLER_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_IAV_PRIMULA_KEM_HANDLER_HPP

#include "score/crypto/src/daemon/provider/score_provider/operations/kem/score_kem_handler.hpp"
#include "score/iav_primula/include/iav_primula_ffi.h"

namespace score::crypto::daemon::provider::score_provider::iav_primula
{

/// @brief IAV-Primula implementation of the provider-neutral KEM handler.
class IavPrimulaKemHandler final : public operations::kem::ScoreKemHandler
{
  public:
    /// @brief Create an IAV-Primula KEM handler.
    ///
    /// Takes ownership of the operation executor and stores the selected
    /// ML-KEM algorithm.
    ///
    /// @param executor Provider-neutral executor for KEM operations.
    /// @param algorithm ML-KEM algorithm identifier.
    IavPrimulaKemHandler(std::unique_ptr<operations::kem::KemExecutor> executor, common::AlgorithmId algorithm);
    ~IavPrimulaKemHandler() override = default;

    IavPrimulaKemHandler(const IavPrimulaKemHandler&) = delete;
    IavPrimulaKemHandler& operator=(const IavPrimulaKemHandler&) = delete;
    IavPrimulaKemHandler(const IavPrimulaKemHandler&&) = delete;
    IavPrimulaKemHandler& operator=(const IavPrimulaKemHandler&&) = delete;

    /// @brief Bind an optional IAV-Primula key to the operation context.
    ///
    /// A native key is required for decapsulation but not for key generation
    /// or encapsulation.
    ///
    /// @param init_params Context initialization parameters, including an
    ///                    optional bound key handler.
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> InitializeContext(
        const handler::InitializationParams& init_params) override;
    /// @brief Generate a KEM key pair and return its public key.
    ///
    /// The native private key is released before the operation returns.
    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> GenerateKeyPair() override;
    /// @brief Encapsulate a shared secret using a public key.
    ///
    /// The response contains the ciphertext followed by the shared secret.
    ///
    /// @param request Request containing the peer public key.
    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> Encapsulate(
        const common::RequestParameter& request) override;
    /// @brief Decapsulate a ciphertext using the bound private key.
    ///
    /// @param request Request containing the ciphertext.
    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> Decapsulate(
        const common::RequestParameter& request) override;

  private:
    /// @brief Map the configured algorithm to the corresponding IAV-Primula enum.
    ///
    /// @return The mapped algorithm, or kUnsupportedAlgorithm if unsupported.
    [[nodiscard]] Expected<iav_algorithm, common::DaemonErrorCode> GetAlgorithm() const noexcept;
    iav_primula_key_handle* m_key{nullptr};  ///< Non-owning handle borrowed from the bound key handler.
};

}  // namespace score::crypto::daemon::provider::score_provider::iav_primula

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_IAV_PRIMULA_KEM_HANDLER_HPP

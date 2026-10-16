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

/// @file iav_primula_handler_factory.hpp
/// @brief Handler factory for IAV-Primula operations.

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_IAV_PRIMULA_HANDLER_FACTORY_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_IAV_PRIMULA_HANDLER_FACTORY_HPP

#include "score/crypto/src/daemon/provider/score_provider/operations/factory/score_handler_factory.hpp"
#include "score/result/result.h"

namespace score::crypto::daemon::provider::score_provider::iav_primula
{

/// @brief Factory for IAV-Primula SIGN, VERIFY, and KEM handlers.
///
/// Validates the requested PQC algorithm and creates the corresponding
/// IAV-Primula handler with its provider-neutral operation executor.
/// Unsupported algorithm families result in kUnsupportedAlgorithm.
class IavPrimulaHandlerFactory final
    : public ::score::crypto::daemon::provider::score_provider::operations::factory::ScoreHandlerFactory
{
  public:
    /// @brief Create an IAV-Primula handler factory.
    ///
    /// @param key_factory Factory used for provider-specific key operations.
    /// @param slot_handler Key-slot handler used for persistent key operations.
    /// @param km_service Key-management service shared with the handlers.
    IavPrimulaHandlerFactory(std::shared_ptr<key_management::IKeyFactory> key_factory,
                             std::shared_ptr<key_management::IKeySlotHandler> slot_handler,
                             key_management::KeyManagementService::Sptr km_service);

    ~IavPrimulaHandlerFactory() override = default;

    IavPrimulaHandlerFactory(const IavPrimulaHandlerFactory&) = delete;
    IavPrimulaHandlerFactory& operator=(const IavPrimulaHandlerFactory&) = delete;
    IavPrimulaHandlerFactory(IavPrimulaHandlerFactory&&) = delete;
    IavPrimulaHandlerFactory& operator=(IavPrimulaHandlerFactory&&) = delete;

  protected:
    /// @brief Create a handler for a supported ML-DSA signature algorithm.
    ///
    /// @return A signature handler, or kUnsupportedAlgorithm if the algorithm
    ///         is not an ML-DSA signature algorithm.
    [[nodiscard]] ::score::Result<::score::crypto::daemon::provider::handler::Handler::Sptr> CreateSignHandler(
        const common::AlgorithmId& algorithm) override;

    /// @brief Create a handler for a supported ML-DSA verification algorithm.
    ///
    /// @return A verification handler, or kUnsupportedAlgorithm if the
    ///         algorithm is not an ML-DSA signature algorithm.
    [[nodiscard]] ::score::Result<::score::crypto::daemon::provider::handler::Handler::Sptr> CreateVerifyHandler(
        const common::AlgorithmId& algorithm) override;

    /// @brief Create a handler for a supported ML-KEM algorithm.
    ///
    /// @return A KEM handler, or kUnsupportedAlgorithm if the algorithm is not
    ///         an ML-KEM algorithm.
    [[nodiscard]] ::score::Result<::score::crypto::daemon::provider::handler::Handler::Sptr> CreateKemHandler(
        const common::AlgorithmId& algorithm) override;
};

}  // namespace score::crypto::daemon::provider::score_provider::iav_primula

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_IAV_PRIMULA_HANDLER_FACTORY_HPP

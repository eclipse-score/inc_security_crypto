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

/// @file score_kem_handler.hpp
/// @brief Provider-neutral base handler for KEM operations.

#ifndef SCORE_CRYPTO_DAEMON_SCORE_PROVIDER_KEM_HANDLER_HPP
#define SCORE_CRYPTO_DAEMON_SCORE_PROVIDER_KEM_HANDLER_HPP

#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/handler/i_handler.hpp"
#include <memory>
#include <utility>

namespace score::crypto::daemon::provider::score_provider::operations::kem
{

class KemExecutor;

/// @brief Provider-neutral base handler for one-shot KEM operations.
///
/// Delegates operation dispatch to the injected KemExecutor. Concrete
/// provider handlers override the typed KEM methods to implement key
/// generation, encapsulation, and decapsulation.
class ScoreKemHandler : public handler::Handler
{
  public:
    /// @brief Create a provider-neutral KEM handler.
    ///
    /// @param executor Executor used to dispatch KEM operations.
    /// @param algorithm Algorithm identifier handled by this instance.
    ScoreKemHandler(std::unique_ptr<KemExecutor>, common::AlgorithmId);
    ~ScoreKemHandler() override;

    ScoreKemHandler(const ScoreKemHandler&) = delete;
    ScoreKemHandler& operator=(const ScoreKemHandler&) = delete;
    ScoreKemHandler(ScoreKemHandler&&) = delete;
    ScoreKemHandler& operator=(ScoreKemHandler&&) = delete;

    /// @brief Delegate one KEM operation to the injected executor.
    Expected<common::ResponseParameters, common::DaemonErrorCode> Execute(const common::OperationIdentifier&,
                                                                          common::RequestParameters&) override;

    /// @brief Initialize the KEM operation context.
    Expected<std::monostate, common::DaemonErrorCode> InitializeContext(const handler::InitializationParams&) override;

    /// @brief Reset the KEM handler state.
    Expected<std::monostate, common::DaemonErrorCode> Reset() override;

    /// @brief Generate a KEM key pair.
    ///
    /// Concrete providers override this method to return the generated public
    /// key or provider-specific key-generation output.
    virtual Expected<common::ResponseParameters, common::DaemonErrorCode> GenerateKeyPair();

    /// @brief Encapsulate a shared secret using a public key.
    ///
    /// Concrete providers override this method to return the ciphertext and
    /// shared secret.
    virtual Expected<common::ResponseParameters, common::DaemonErrorCode> Encapsulate(const common::RequestParameter&);

    /// @brief Decapsulate a ciphertext using the bound private key.
    ///
    /// Concrete providers override this method to return the shared secret.
    virtual Expected<common::ResponseParameters, common::DaemonErrorCode> Decapsulate(const common::RequestParameter&);

  protected:
    common::AlgorithmId m_algorithm;  ///< Algorithm handled by this instance.

  private:
    std::unique_ptr<KemExecutor> m_executor;  ///< Owns the operation dispatcher.
};
}  // namespace score::crypto::daemon::provider::score_provider::operations::kem

#endif  // SCORE_CRYPTO_DAEMON_SCORE_PROVIDER_KEM_HANDLER_HPP

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

/// @file kem_executor.hpp
/// @brief Operation dispatcher for provider-neutral KEM handlers.

#ifndef SCORE_CRYPTO_DAEMON_SCORE_PROVIDER_KEM_EXECUTOR_HPP
#define SCORE_CRYPTO_DAEMON_SCORE_PROVIDER_KEM_EXECUTOR_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"

namespace score::crypto::daemon::provider::score_provider::operations::kem
{

class ScoreKemHandler;

/// @brief Stateless dispatcher for one-shot KEM operations.
///
/// The executor validates operation parameter counts and dispatches key
/// generation, encapsulation, decapsulation, and reset operations to
/// ScoreKemHandler.
class KemExecutor final
{
  public:
    /// @brief Execute one KEM operation.
    ///
    /// Dispatches the operation identified by the operation action to the
    /// corresponding ScoreKemHandler method.
    ///
    /// @param handler KEM handler receiving the operation.
    /// @param operation Operation identifier containing the KEM action.
    /// @param request Operation parameters.
    /// @return Operation response, or a daemon error if the parameters or
    ///         operation are invalid.
    Expected<common::ResponseParameters, common::DaemonErrorCode> Execute(ScoreKemHandler& handler,
                                                                          const common::OperationIdentifier& operation,
                                                                          common::RequestParameters& request);
};
}  // namespace score::crypto::daemon::provider::score_provider::operations::kem

#endif  // SCORE_CRYPTO_DAEMON_SCORE_PROVIDER_KEM_EXECUTOR_HPP

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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_HASH_HASH_EXECUTOR_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_HASH_HASH_EXECUTOR_HPP

#include "score/crypto/common/types.hpp"
#include "score/crypto/daemon/common/daemon_error.hpp"
#include "score/crypto/daemon/common/types.hpp"

#include <variant>

namespace score::crypto::daemon::provider::score_provider::operations::hash
{

class ScoreHashHandler;

/// @brief Stateless executor implementing orchestration and visitor pattern for hash
///        operations under the score interface family.
///
/// Responsibilities:
///   - Orchestrates operation flow and validates state transitions
///   - Routes operations to ScoreHashHandler typed methods via visitor pattern
///   - Decouples operation invocation from handler implementation
class HashExecutor
{
  public:
    /// @brief Execute a hash operation on the given handler.
    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> Execute(
        ScoreHashHandler& handler,
        const common::OperationIdentifier& operationId,
        common::RequestParameters& request);

  private:
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> ExecuteInit(ScoreHashHandler& handler,
                                                                                common::RequestParameters& request);

    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> ExecuteUpdate(ScoreHashHandler& handler,
                                                                                  common::RequestParameters& request);

    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> ExecuteFinalize(
        ScoreHashHandler& handler,
        common::RequestParameters& request);

    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> ExecuteSingleShot(
        ScoreHashHandler& handler,
        common::RequestParameters& request);

    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> ExecuteReset(ScoreHashHandler& handler,
                                                                                 common::RequestParameters& request);

    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> GetDigestSize(
        const ScoreHashHandler& handler,
        common::RequestParameters& request);

    [[nodiscard]] static Expected<std::monostate, common::DaemonErrorCode> ValidateStreamTransition(
        common::OperationAction action,
        common::StreamOperationState currentState,
        common::StreamOperationState& nextState);
};

}  // namespace score::crypto::daemon::provider::score_provider::operations::hash

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_HASH_HASH_EXECUTOR_HPP

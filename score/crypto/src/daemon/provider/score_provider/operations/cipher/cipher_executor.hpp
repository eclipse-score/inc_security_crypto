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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_CIPHER_CIPHER_EXECUTOR_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_CIPHER_CIPHER_EXECUTOR_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"

namespace score::crypto::daemon::provider::score_provider::operations::cipher
{

class ScoreCipherHandler;

/// @brief Stateless executor implementing the strategy / visitor pattern for
///        symmetric cipher operations under the score interface family.
///
/// Mirrors HashExecutor and MacExecutor:
///   - Orchestrates operation flow and validates stream state transitions
///   - Extracts IPC buffer parameters from RequestParameters
///   - Routes operations to the typed ScoreCipherHandler methods
///   - Packs results back into ResponseParameters
class CipherExecutor
{
  public:
    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> Execute(
        ScoreCipherHandler& handler,
        const common::OperationIdentifier& operationId,
        common::RequestParameters& request);

  private:
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> ExecuteInit(ScoreCipherHandler& handler,
                                                                                common::RequestParameters& request);

    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> ExecuteUpdate(
        ScoreCipherHandler& handler,
        common::RequestParameters& request);

    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> ExecuteFinalize(
        ScoreCipherHandler& handler,
        common::RequestParameters& request);

    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> ExecuteSingleShot(
        ScoreCipherHandler& handler,
        common::RequestParameters& request);

    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> ExecuteReset(ScoreCipherHandler& handler,
                                                                                 common::RequestParameters& request);

    [[nodiscard]] static Expected<std::monostate, common::DaemonErrorCode> ValidateStreamTransition(
        common::OperationAction action,
        common::StreamOperationState currentState,
        common::StreamOperationState& nextState);
};

}  // namespace score::crypto::daemon::provider::score_provider::operations::cipher

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_CIPHER_CIPHER_EXECUTOR_HPP

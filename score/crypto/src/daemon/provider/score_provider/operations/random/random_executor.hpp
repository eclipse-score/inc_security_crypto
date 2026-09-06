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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_RANDOM_RANDOM_EXECUTOR_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_RANDOM_RANDOM_EXECUTOR_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"

namespace score::crypto::daemon::provider::score_provider::operations::random
{

class ScoreRandomHandler;

/// @brief Stateless executor for random number generation under the score
///        interface family.
///
/// Simpler than the streaming executors: there is no state machine to validate,
/// only parameter extraction, a request-size bound, and result packing.
class RandomExecutor
{
  public:
    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> Execute(
        ScoreRandomHandler& handler,
        const common::OperationIdentifier& operationId,
        common::RequestParameters& request);

  private:
    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> ExecuteGenerate(
        ScoreRandomHandler& handler,
        common::RequestParameters& request);

    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> ExecuteSeed(
        ScoreRandomHandler& handler,
        common::RequestParameters& request);
};

}  // namespace score::crypto::daemon::provider::score_provider::operations::random

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_RANDOM_RANDOM_EXECUTOR_HPP

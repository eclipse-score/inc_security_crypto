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

#include "score/crypto/src/daemon/provider/score_provider/operations/random/random_executor.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/random_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/handler/src/handler_utils.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/random/score_random_handler.hpp"

#include <cstdint>
#include <utility>
#include <variant>

namespace score::crypto::daemon::provider::score_provider::operations::random
{

namespace handler = ::score::crypto::daemon::provider::handler;
using common::DaemonErrorCode;
using common::RequestParameters;
using common::ResponseParameters;
using ::score::crypto::daemon::provider::handler::handler_utils::CheckAndGetSpan;

Expected<ResponseParameters, DaemonErrorCode> RandomExecutor::Execute(ScoreRandomHandler& handler_ref,
                                                                      const common::OperationIdentifier& operationId,
                                                                      RequestParameters& request)
{
    namespace ops = handler::random_handler_operations;

    if (operationId.operationAction == ops::RANDOM_GENERATE)
    {
        return ExecuteGenerate(handler_ref, request);
    }

    if (operationId.operationAction == ops::RANDOM_SEED)
    {
        return ExecuteSeed(handler_ref, request);
    }

    return make_unexpected(DaemonErrorCode::kInvalidOperation);
}

Expected<ResponseParameters, DaemonErrorCode> RandomExecutor::ExecuteGenerate(ScoreRandomHandler& handler_ref,
                                                                              RequestParameters& request)
{
    // request[0] = caller-provided output buffer; its length is the byte count.
    if (request.empty())
    {
        return make_unexpected(DaemonErrorCode::kInsufficientParameters);
    }

    const auto outputSpan = CheckAndGetSpan<std::uint8_t>(request[0]);
    if (!outputSpan.has_value())
    {
        return make_unexpected(outputSpan.error());
    }

    // Bound the work a single client request can trigger in the daemon.
    if (outputSpan.value().size() > ScoreRandomHandler::kMaxGenerateBytes)
    {
        return make_unexpected(DaemonErrorCode::kQuotaExceeded);
    }

    auto generated = handler_ref.GenerateRandom(outputSpan.value());
    if (!generated.has_value())
    {
        return make_unexpected(generated.error());
    }

    ResponseParameters response;
    response.push_back(static_cast<std::uint64_t>(generated.value()));
    return response;
}

Expected<ResponseParameters, DaemonErrorCode> RandomExecutor::ExecuteSeed(ScoreRandomHandler& handler_ref,
                                                                          RequestParameters& request)
{
    if (request.empty())
    {
        return make_unexpected(DaemonErrorCode::kInsufficientParameters);
    }

    auto seeded = handler_ref.SeedRandom(request[0]);
    if (!seeded.has_value())
    {
        return make_unexpected(seeded.error());
    }

    return ResponseParameters{};
}

}  // namespace score::crypto::daemon::provider::score_provider::operations::random

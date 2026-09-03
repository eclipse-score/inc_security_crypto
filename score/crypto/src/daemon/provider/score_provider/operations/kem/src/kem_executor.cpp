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

#include "score/crypto/src/daemon/provider/score_provider/operations/kem/kem_executor.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/kem_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/kem/score_kem_handler.hpp"

namespace score::crypto::daemon::provider::score_provider::operations::kem
{

namespace ops = ::score::crypto::daemon::provider::handler::kem_handler_operations;

Expected<common::ResponseParameters, common::DaemonErrorCode> KemExecutor::Execute(
    ScoreKemHandler& handler,
    const common::OperationIdentifier& operation,
    common::RequestParameters& request)
{
    // Dispatch the KEM operation and enforce the parameter requirements for
    // each operation type.
    switch (operation.operationAction)
    {
        case ops::KEM_KEYGEN:
        {
            if (!request.empty())
            {
                return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
            }
            return handler.GenerateKeyPair();
        }
        case ops::KEM_ENCAPSULATE:
        {
            if (request.empty())
            {
                return make_unexpected(common::DaemonErrorCode::kInsufficientParameters);
            }
            return handler.Encapsulate(request[0]);
        }
        case ops::KEM_DECAPSULATE:
        {
            if (request.empty())
            {
                return make_unexpected(common::DaemonErrorCode::kInsufficientParameters);
            }
            return handler.Decapsulate(request[0]);
        }
        case ops::KEM_RESET:
        {
            auto reset_result = handler.Reset();
            // Reset does not produce response data; propagate any handler error.
            if (!reset_result.has_value())
            {
                return make_unexpected(reset_result.error());
            }
            return {};
        }
        default:
        {  // Reject operation actions that are not part of the KEM operation namespace.
            return make_unexpected(common::DaemonErrorCode::kInvalidOperation);
        }
    }
}
}  // namespace score::crypto::daemon::provider::score_provider::operations::kem

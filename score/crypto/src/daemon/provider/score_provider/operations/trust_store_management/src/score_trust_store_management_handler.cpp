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

#include "score/crypto/src/daemon/provider/score_provider/operations/trust_store_management/score_trust_store_management_handler.hpp"
#include "score/mw/log/logging.h"

#include <string_view>

namespace score::crypto::daemon::provider::score_provider::operations::trust_store_management
{

namespace
{
constexpr std::string_view LOG_PREFIX = "[SCORE_TRUST_STORE_MGMT_HANDLER] ";
}

ScoreTrustStoreManagementHandler::ScoreTrustStoreManagementHandler(
    std::unique_ptr<crypto_executor::TrustStoreManagementExecutor> executor)
    : m_executor{std::move(executor)}, m_ctx{}
{
}

Expected<std::monostate, common::DaemonErrorCode> ScoreTrustStoreManagementHandler::InitializeContext(
    const handler::InitializationParams& init_params)
{
    m_ctx.client_id = init_params.client_id;
    m_ctx.context_node_id = init_params.context_node_id;
    if (init_params.provider_id != common::kInvalidProviderId)
        m_ctx.provider_id = init_params.provider_id;
    return std::monostate{};
}

Expected<common::ResponseParameters, common::DaemonErrorCode> ScoreTrustStoreManagementHandler::Execute(
    const common::OperationIdentifier& operationId,
    common::RequestParameters& request)
{
    if (!m_executor)
    {
        score::mw::log::LogError() << LOG_PREFIX << "Execute: executor not injected";
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }
    return m_executor->Execute(m_ctx, operationId, request);
}

Expected<std::monostate, common::DaemonErrorCode> ScoreTrustStoreManagementHandler::Reset()
{
    return std::monostate{};
}

}  // namespace score::crypto::daemon::provider::score_provider::operations::trust_store_management

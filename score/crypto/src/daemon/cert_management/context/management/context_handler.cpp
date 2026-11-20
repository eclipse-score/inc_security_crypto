/*******************************************************************************
 *
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
 *******************************************************************************
 */

#include "score/crypto/src/daemon/cert_management/context/management/context_handler.hpp"

#include "score/mw/log/logging.h"

#include <string_view>
#include <utility>
#include <variant>

namespace score::crypto::daemon::cert_management
{

namespace
{

constexpr std::string_view kLogPrefix{"[CERT_MGMT_CTX] "};

}  // namespace

CertManagementContextHandler::CertManagementContextHandler(std::shared_ptr<const CertManagementExecutor> executor)
    : m_executor{std::move(executor)}
{
}

score::crypto::Expected<std::monostate, common::DaemonErrorCode> CertManagementContextHandler::InitializeContext(
    const common::InitializationParams& init_params)
{
    if (m_initialized)
    {
        score::mw::log::LogError() << kLogPrefix << "Context is already initialized";
        return score::crypto::make_unexpected(common::DaemonErrorCode::kInvalidOperation);
    }

    m_ctx.provider_id = init_params.provider_id;
    m_ctx.client_id = init_params.client_id;
    m_ctx.context_node_id = init_params.context_node_id;
    m_initialized = true;
    return std::monostate{};
}

score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> CertManagementContextHandler::Execute(
    const common::OperationIdentifier& operation_id,
    common::RequestParameters& request)
{
    if (!m_initialized)
    {
        score::mw::log::LogError() << kLogPrefix << "Operation received before context initialization";
        return score::crypto::make_unexpected(common::DaemonErrorCode::kInvalidOperation);
    }

    return m_executor->Execute(m_ctx, operation_id, request);
}

score::crypto::Expected<std::monostate, common::DaemonErrorCode> CertManagementContextHandler::Reset()
{
    return std::monostate{};
}

}  // namespace score::crypto::daemon::cert_management

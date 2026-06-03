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

#include "score/crypto/daemon/provider/pkcs11/operations/key_management/pkcs11_key_management_handler.hpp"

#include "score/crypto/daemon/provider/pkcs11/pkcs11_provider.hpp"

#include "score/mw/log/logging.h"

namespace score::crypto::daemon::provider::pkcs11
{

Pkcs11KeyManagementHandler::Pkcs11KeyManagementHandler(std::shared_ptr<Pkcs11Provider> provider,
                                                       std::unique_ptr<crypto_executor::KeyManagementExecutor> executor,
                                                       common::ProviderId provider_id)
    : m_provider{std::move(provider)}, m_executor{std::move(executor)}, m_ctx{provider_id, 0U, 0U}
{
}

Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Pkcs11KeyManagementHandler::InitializeContext(
    const handler::InitializationParams& init_params)
{
    m_ctx.client_id = init_params.client_id;
    m_ctx.context_node_id = init_params.context_node_id;
    if (init_params.provider_id != common::kInvalidProviderId)
    {
        m_ctx.provider_id = init_params.provider_id;
    }
    return std::monostate{};
}

Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Pkcs11KeyManagementHandler::Reset()
{
    return std::monostate{};
}

Expected<common::ResponseParameters, score::crypto::daemon::common::DaemonErrorCode>
Pkcs11KeyManagementHandler::Execute(const common::OperationIdentifier& operationId, common::RequestParameters& request)
{
    if (!m_executor)
    {
        score::mw::log::LogError() << LOG_PREFIX << "Execute: executor not injected";
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }
    return m_executor->Execute(m_ctx, operationId, request);
}

static constexpr const char* kSupportedAlgorithms[] =
    {"HMAC-SHA256", "HMAC-SHA384", "HMAC-SHA512", "AES-128", "AES-192", "AES-256"};

bool Pkcs11KeyManagementHandler::IsAlgorithmSupported(const common::AlgorithmId& algorithm) noexcept
{
    for (const char* supported : kSupportedAlgorithms)
    {
        if (algorithm == supported)
        {
            return true;
        }
    }
    return false;
}

}  // namespace score::crypto::daemon::provider::pkcs11

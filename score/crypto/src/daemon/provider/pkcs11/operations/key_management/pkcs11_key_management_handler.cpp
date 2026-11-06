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

#include "score/crypto/src/daemon/provider/pkcs11/operations/key_management/pkcs11_key_management_handler.hpp"

#include "score/crypto/src/daemon/provider/pkcs11/detail/pkcs11_algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/pkcs11_provider.hpp"

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

bool Pkcs11KeyManagementHandler::IsAlgorithmSupported(const AlgorithmDescriptor& algorithm) noexcept
{
    switch (algorithm.key_type)
    {
        case ::score::crypto::KeyType::kSecret:
            // HMAC keys: the MACs this provider computes.
            return detail::LookupMacMechanism(algorithm) != CK_UNAVAILABLE_INFORMATION;
        case ::score::crypto::KeyType::kAes:
            // AES key rows only.
            return (algorithm.category == ::score::crypto::AlgorithmCategory::kKey) &&
                   ((algorithm.key_bits == 128U) || (algorithm.key_bits == 192U) || (algorithm.key_bits == 256U));
        case ::score::crypto::KeyType::kMlDsa:
        case ::score::crypto::KeyType::kMlKem:
        case ::score::crypto::KeyType::kNone:
        case ::score::crypto::KeyType::kEcc:
        case ::score::crypto::KeyType::kRsa:
        case ::score::crypto::KeyType::kEd25519:
            return false;
    }
    return false;
}

}  // namespace score::crypto::daemon::provider::pkcs11

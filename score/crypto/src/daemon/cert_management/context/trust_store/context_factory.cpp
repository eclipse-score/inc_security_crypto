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

#include "score/crypto/src/daemon/cert_management/context/trust_store/context_factory.hpp"

#include "score/crypto/src/daemon/cert_management/context/trust_store/context_handler.hpp"
#include "score/crypto/src/daemon/cert_management/context/trust_store/executor.hpp"

#include <utility>

namespace score::crypto::daemon::cert_management
{

TrustStoreManagementContextFactory::TrustStoreManagementContextFactory(
    std::shared_ptr<const SlotHandlerFactory> parser_source,
    CertManagementService::Sptr service)
    : m_parser_source{std::move(parser_source)}, m_service{std::move(service)}
{
}

score::crypto::Expected<common::Handler::Sptr, common::DaemonErrorCode> TrustStoreManagementContextFactory::Create(
    const common::ContextCreationRequest& /*request*/)
{
    auto parser = m_parser_source->GetCertParser();
    if (!parser.has_value())
    {
        return score::crypto::make_unexpected(parser.error());
    }
    auto executor = std::make_shared<TrustStoreManagementExecutor>(parser.value(), m_service);
    return common::Handler::Sptr{std::make_shared<TrustStoreManagementContextHandler>(std::move(executor))};
}

}  // namespace score::crypto::daemon::cert_management

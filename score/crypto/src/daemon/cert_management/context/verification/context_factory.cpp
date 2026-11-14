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

#include "score/crypto/src/daemon/cert_management/context/verification/context_factory.hpp"

#include "score/crypto/src/daemon/cert_management/context/verification/context_handler.hpp"
#include "score/crypto/src/daemon/cert_management/context/verification/executor.hpp"

#include <array>
#include <optional>
#include <utility>

namespace score::crypto::daemon::cert_management
{

namespace
{

/// Resolves the path validator of the provider that the preference selects. The primary type is tried first and the
/// fallback second. DEFAULT selects the provider that offers certificate management, software first, which is the
/// rule that provider selection applies to other contexts. A provider that supplies no validator does not satisfy the
/// preference.
score::crypto::Expected<std::shared_ptr<provider::cert_management::ICertPathValidator>, common::DaemonErrorCode>
SelectPathValidator(const provider::ProviderManager& provider_manager, const common::ProviderTypePreference& preference)
{
    const std::array<std::optional<common::CryptoProviderType>, 2U> candidates{preference.primary, preference.fallback};
    auto last_error = common::DaemonErrorCode::kProviderNotAvailable;
    for (const auto& candidate : candidates)
    {
        if (!candidate.has_value())
        {
            continue;
        }
        const auto selected =
            (candidate.value() == common::CryptoProviderType::DEFAULT)
                ? provider_manager.GetProviderForCapability(common::ProviderCapability::kCertManagement)
                : provider_manager.GetProvider(candidate.value());
        if (!selected)
        {
            continue;
        }
        auto validator = selected->GetCertPathValidator();
        if (validator)
        {
            return validator;
        }
        last_error = common::DaemonErrorCode::kUnsupportedOperation;
    }
    return score::crypto::make_unexpected(last_error);
}

}  // namespace

CertVerificationContextFactory::CertVerificationContextFactory(std::shared_ptr<const SlotHandlerFactory> parser_source,
                                                               provider::ProviderManager::Sptr provider_manager,
                                                               CertManagementService::Sptr service)
    : m_parser_source{std::move(parser_source)},
      m_provider_manager{std::move(provider_manager)},
      m_service{std::move(service)}
{
}

score::crypto::Expected<common::Handler::Sptr, common::DaemonErrorCode> CertVerificationContextFactory::Create(
    const common::ContextCreationRequest& request)
{
    auto parser = m_parser_source->GetCertParser();
    if (!parser.has_value())
    {
        return score::crypto::make_unexpected(parser.error());
    }
    auto validator = SelectPathValidator(*m_provider_manager, request.provider_type_preference);
    if (!validator.has_value())
    {
        return score::crypto::make_unexpected(validator.error());
    }

    CertVerificationSession::Services services{m_service, std::move(parser.value()), std::move(validator.value())};
    auto executor = std::make_shared<CertVerificationExecutor>();
    return common::Handler::Sptr{
        std::make_shared<CertVerificationContextHandler>(std::move(executor), std::move(services))};
}

}  // namespace score::crypto::daemon::cert_management

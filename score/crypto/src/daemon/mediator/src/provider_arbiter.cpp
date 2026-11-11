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

#include "score/crypto/src/daemon/mediator/src/provider_arbiter.hpp"

#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/provider/handler/i_crypto_handler_factory.hpp"

#include <array>
#include <cstddef>
#include <string>
#include <utility>

namespace score::crypto::daemon::mediator
{

namespace
{

bool IsFallbackEligible(const score::crypto::CryptoErrorCode error) noexcept
{
    return (error == score::crypto::CryptoErrorCode::kUnsupportedOperation) ||
           (error == score::crypto::CryptoErrorCode::kUnsupportedAlgorithm) ||
           (error == score::crypto::CryptoErrorCode::kProviderNotAvailable) ||
           (error == score::crypto::CryptoErrorCode::kIncompatibleKeyType);
}

}  // namespace

ProviderArbiter::ProviderArbiter(provider::ProviderManager::Sptr provider_manager,
                                 key_management::KeyManagementService::Sptr km_service) noexcept
    : m_provider_manager(std::move(provider_manager)), m_km_service(std::move(km_service))
{
}

score::crypto::Expected<std::shared_ptr<provider::IProvider>, score::crypto::CryptoErrorCode>
ProviderArbiter::ResolveProvider(const ProviderSelectionRequest& request,
                                 const common::CryptoProviderType provider_type) const
{
    if (m_km_service && request.key_node_id.has_value())
    {
        const auto resolved_id =
            m_km_service->ResolveTargetProvider(request.client_id, provider_type, request.key_node_id);
        if (!resolved_id.has_value())
        {
            return score::crypto::make_unexpected(common::ToCryptoErrorCode(resolved_id.error()));
        }

        auto resolved_provider = m_provider_manager->GetProvider(resolved_id.value());
        if (!resolved_provider)
        {
            return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kProviderNotAvailable);
        }
        return resolved_provider;
    }

    std::shared_ptr<provider::IProvider> resolved_provider;
    if ((provider_type == common::CryptoProviderType::DEFAULT) &&
        (request.required_capability != common::ProviderCapability::kNone))
    {
        resolved_provider = m_provider_manager->GetProviderForCapability(request.required_capability);
    }
    else
    {
        resolved_provider = m_provider_manager->GetProvider(provider_type);
    }
    if (!resolved_provider)
    {
        return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kProviderNotAvailable);
    }
    return resolved_provider;
}

score::crypto::Expected<ProviderHandlerSelection, score::crypto::CryptoErrorCode> ProviderArbiter::Select(
    const ProviderSelectionRequest& request) const
{
    const std::array<std::optional<common::CryptoProviderType>, 2U> candidates{request.provider_type_preference.primary,
                                                                               request.provider_type_preference.fallback};
    std::optional<common::ProviderId> previous_provider_id{};
    auto last_error = score::crypto::CryptoErrorCode::kProviderNotAvailable;

    for (std::size_t candidate_index = 0U; candidate_index < candidates.size(); ++candidate_index)
    {
        if (!candidates[candidate_index].has_value())
        {
            continue;
        }

        auto candidate_result = ResolveProvider(request, candidates[candidate_index].value());
        if (!candidate_result.has_value())
        {
            last_error = candidate_result.error();
            if (!IsFallbackEligible(last_error))
            {
                break;
            }
            continue;
        }
        auto candidate = candidate_result.value();

        if (previous_provider_id.has_value() && (previous_provider_id.value() == candidate->GetProviderId()))
        {
            continue;
        }
        previous_provider_id = candidate->GetProviderId();

        if ((request.required_capability != common::ProviderCapability::kNone) &&
            !common::HasCapability(candidate->GetProviderCapabilities(), request.required_capability))
        {
            last_error = score::crypto::CryptoErrorCode::kUnsupportedOperation;
            continue;
        }

        const auto crypto_ops = candidate->GetCryptoHandlerFactory();
        if (!crypto_ops)
        {
            last_error = score::crypto::CryptoErrorCode::kUnsupportedOperation;
            continue;
        }

        auto create_result =
            request.algorithm.has_value()
                ? crypto_ops->CreateHandler(std::string(request.context_type), request.algorithm.value())
                : crypto_ops->CreateKeyManagementHandler();
        if (create_result.has_value())
        {
            return ProviderHandlerSelection{
                std::move(candidate), std::move(create_result).value(), candidate_index > 0U};
        }

        last_error = static_cast<score::crypto::CryptoErrorCode>(*create_result.error());
        if (!IsFallbackEligible(last_error))
        {
            break;
        }
    }

    return score::crypto::make_unexpected(last_error);
}

}  // namespace score::crypto::daemon::mediator

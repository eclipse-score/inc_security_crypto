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

#include "score/crypto/src/daemon/provider/provider_capability_query.hpp"

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/daemon/common/context_types.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/i_key_factory.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_management_operations.hpp"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"
#include "score/crypto/src/daemon/provider/handler/i_crypto_handler_factory.hpp"
#include "score/mw/log/logging.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <utility>
#include <variant>

namespace score::crypto::daemon::provider
{

namespace
{

namespace protocol = control_plane::protocol;
namespace mediator_ops = mediator::operations;

std::vector<std::uint8_t> ToBytes(std::string_view text)
{
    return std::vector<std::uint8_t>(text.begin(), text.end());
}

// SYSTEM_CAPABILITIES reports a subset of the catalog, and provider names are
// limited at registration; both must fit the public structs the client fills.
static_assert(std::size(score::crypto::kAlgorithmCatalog) <= SystemCapabilities::kMaxAlgorithms,
              "SystemCapabilities cannot hold every catalog algorithm");
static_assert(common::kMaxProviderNameLength == decltype(ProviderInfo::name)::capacity(),
              "provider name limit differs from ProviderInfo::name capacity");

constexpr bool AllCatalogNamesFitAlgorithmId() noexcept
{
    for (const auto& row : score::crypto::kAlgorithmCatalog)
    {
        if (row.name.size() > AlgorithmId::capacity())
        {
            return false;
        }
    }
    return true;
}
static_assert(AllCatalogNamesFitAlgorithmId(), "catalog algorithm name exceeds AlgorithmId capacity");

/// Context types reported as capability operations, in reporting order.
constexpr std::array<std::string_view, 6U> kCapabilityContexts{common::context_types::kHash,
                                                               common::context_types::kMac,
                                                               common::context_types::kCipher,
                                                               common::context_types::kSign,
                                                               common::context_types::kVerify,
                                                               common::context_types::kRandom};

/// Key factory operations reported as capability operations, in reporting order.
constexpr std::array<std::pair<common::OperationAction, std::string_view>, 1U> kCapabilityKeyOperations{
    {{key_management::operations::KEY_GENERATE, mediator_ops::capability_operations::kGenerateKey}}};

constexpr bool FitsOperationName(std::string_view name) noexcept
{
    return name.size() <= decltype(AlgorithmCapabilities::operations)::value_type::capacity();
}

constexpr bool AllOperationNamesFit() noexcept
{
    for (const auto name : kCapabilityContexts)
    {
        if (!FitsOperationName(name))
        {
            return false;
        }
    }
    for (const auto& entry : kCapabilityKeyOperations)
    {
        if (!FitsOperationName(entry.second))
        {
            return false;
        }
    }
    return true;
}

// The client copies the names into AlgorithmCapabilities without truncating.
static_assert(std::size(kCapabilityContexts) + std::size(kCapabilityKeyOperations) <=
                  AlgorithmCapabilities::kMaxOperations,
              "AlgorithmCapabilities cannot hold every capability operation");
static_assert(AllOperationNamesFit(), "capability operation name exceeds AlgorithmCapabilities::operations capacity");

/// Appends an operation count and the operation names to @p response.
void AppendOperations(protocol::OperationResponseBuilder& response, const std::vector<std::string_view>& names)
{
    response.return_value_uint16(static_cast<std::uint16_t>(names.size()));
    for (const auto name : names)
    {
        response.return_value_data_buffer_out(ToBytes(name));
    }
}

}  // namespace

const std::array<common::OperationAction, 3U> ProviderCapabilityQuery::kOperations{mediator_ops::PROVIDER_INFO,
                                                                                   mediator_ops::QUERY_CAPABILITIES,
                                                                                   mediator_ops::SYSTEM_CAPABILITIES};

ProviderCapabilityQuery::ProviderCapabilityQuery(ProviderManager::Sptr provider_manager)
    : m_provider_manager{std::move(provider_manager)}
{
}

bool ProviderCapabilityQuery::Serves(common::OperationAction action) noexcept
{
    return std::find(kOperations.begin(), kOperations.end(), action) != kOperations.end();
}

bool ProviderCapabilityQuery::Handle(const protocol::ControlRequest& /*request*/,
                                     const protocol::SingleOperationRequest& operation,
                                     protocol::OperationResponseBuilder& responseBuilder) const
{
    const auto action = operation.operationId.operationAction;
    if (action == mediator_ops::PROVIDER_INFO)
    {
        return HandleProviderInfo(operation, responseBuilder);
    }
    if (action == mediator_ops::QUERY_CAPABILITIES)
    {
        return HandleQueryCapabilities(operation, responseBuilder);
    }
    if (action == mediator_ops::SYSTEM_CAPABILITIES)
    {
        return HandleSystemCapabilities(operation, responseBuilder);
    }
    responseBuilder.operation(operation.operationId)
        .return_error(score::crypto::CryptoErrorCode::kUnsupportedOperation);
    return false;
}

std::vector<std::shared_ptr<IProvider>> ProviderCapabilityQuery::InitializedProviders() const
{
    std::vector<std::shared_ptr<IProvider>> providers;
    if (m_provider_manager == nullptr)
    {
        return providers;
    }
    std::vector<common::ProviderName> names;
    m_provider_manager->ForEachProvider([&names](const common::ProviderName& name, const auto& /*instance*/) {
        names.push_back(name);
    });
    for (const auto& name : names)
    {
        // GetProvider() initializes lazily and returns nullptr if that fails.
        if (auto provider = m_provider_manager->GetProvider(name))
        {
            providers.push_back(std::move(provider));
        }
    }
    std::sort(providers.begin(), providers.end(), [](const auto& lhs, const auto& rhs) {
        return lhs->GetProviderId() < rhs->GetProviderId();
    });
    return providers;
}

std::vector<std::string_view> ProviderCapabilityQuery::CollectCapabilities(
    const std::vector<std::shared_ptr<IProvider>>& providers,
    const ::score::crypto::AlgorithmDescriptor& algorithm)
{
    std::array<bool, std::size(kCapabilityContexts)> accepted{};
    std::array<bool, std::size(kCapabilityKeyOperations)> key_accepted{};
    for (const auto& provider : providers)
    {
        if (const auto factory = provider->GetCryptoHandlerFactory())
        {
            for (std::size_t i = 0U; i < std::size(kCapabilityContexts); ++i)
            {
                accepted.at(i) = accepted.at(i) ||
                                 factory->IsAlgorithmSupported(common::HandlerId{kCapabilityContexts.at(i)}, algorithm);
            }
        }
        if (const auto key_factory = provider->GetKeyFactory())
        {
            for (std::size_t i = 0U; i < std::size(kCapabilityKeyOperations); ++i)
            {
                key_accepted.at(i) = key_accepted.at(i) ||
                                     key_factory->IsOperationSupported(kCapabilityKeyOperations.at(i).first, algorithm);
            }
        }
    }

    std::vector<std::string_view> result;
    for (std::size_t i = 0U; i < std::size(kCapabilityContexts); ++i)
    {
        if (accepted.at(i))
        {
            result.push_back(kCapabilityContexts.at(i));
        }
    }
    for (std::size_t i = 0U; i < std::size(kCapabilityKeyOperations); ++i)
    {
        if (key_accepted.at(i))
        {
            result.push_back(kCapabilityKeyOperations.at(i).second);
        }
    }
    return result;
}

bool ProviderCapabilityQuery::HandleProviderInfo(const protocol::SingleOperationRequest& operation,
                                                 protocol::OperationResponseBuilder& responseBuilder) const
{
    const auto* id_param =
        operation.parameters.empty() ? nullptr : std::get_if<std::uint64_t>(&operation.parameters[0]);
    if ((id_param == nullptr) || (*id_param >= common::kInvalidProviderId) || (m_provider_manager == nullptr))
    {
        responseBuilder.operation(operation.operationId).return_error(score::crypto::CryptoErrorCode::kInvalidArgument);
        return false;
    }

    const auto provider = m_provider_manager->GetProvider(static_cast<common::ProviderId>(*id_param));
    if (provider == nullptr)
    {
        responseBuilder.operation(operation.operationId).return_error(score::crypto::CryptoErrorCode::kInvalidArgument);
        return false;
    }

    const auto& name = provider->GetProviderName();
    responseBuilder.operation(operation.operationId)
        .return_value_uint16(provider->GetProviderId())
        .return_value_uint8(mediator_ops::EncodeProviderType(m_provider_manager->GetProviderType(name)))
        .return_value_data_buffer_out(ToBytes(name))
        .return_success();
    return true;
}

bool ProviderCapabilityQuery::HandleQueryCapabilities(const protocol::SingleOperationRequest& operation,
                                                      protocol::OperationResponseBuilder& responseBuilder) const
{
    const auto* name_param =
        operation.parameters.empty() ? nullptr : std::get_if<std::string_view>(&operation.parameters[0]);
    if (name_param == nullptr)
    {
        responseBuilder.operation(operation.operationId).return_error(score::crypto::CryptoErrorCode::kInvalidArgument);
        return false;
    }

    // An empty name asks for the default generator, as it does when a RANDOM
    // context is created. A name the catalog does not know is served by no provider.
    const auto algorithm = name_param->empty()
                               ? score::crypto::GetAlgorithmDescriptor(score::crypto::Algorithm::kCtrDrbg)
                               : score::crypto::GetAlgorithmDescriptor(*name_param);
    auto& response = responseBuilder.operation(operation.operationId);
    AppendOperations(response,
                     algorithm.has_value() ? CollectCapabilities(InitializedProviders(), algorithm.value())
                                           : std::vector<std::string_view>{});
    response.return_success();
    return true;
}

bool ProviderCapabilityQuery::HandleSystemCapabilities(const protocol::SingleOperationRequest& operation,
                                                       protocol::OperationResponseBuilder& responseBuilder) const
{
    const auto providers = InitializedProviders();
    if (providers.size() > SystemCapabilities::kMaxProviders)
    {
        score::mw::log::LogError() << "[PROVIDER_CAPABILITY_QUERY] SYSTEM_CAPABILITIES: " << providers.size()
                                   << " providers exceed the client limit of " << SystemCapabilities::kMaxProviders;
        responseBuilder.operation(operation.operationId)
            .return_error(score::crypto::CryptoErrorCode::kInsufficientBufferSize);
        return false;
    }
    auto& response = responseBuilder.operation(operation.operationId);

    response.return_value_uint16(static_cast<std::uint16_t>(providers.size()));
    for (const auto& provider : providers)
    {
        const auto& name = provider->GetProviderName();
        response.return_value_uint16(provider->GetProviderId())
            .return_value_uint8(mediator_ops::EncodeProviderType(m_provider_manager->GetProviderType(name)))
            .return_value_data_buffer_out(ToBytes(name));
    }

    std::vector<std::pair<std::string_view, std::vector<std::string_view>>> supported;
    for (const auto& row : score::crypto::kAlgorithmCatalog)
    {
        auto ops = CollectCapabilities(providers, row);
        if (!ops.empty())
        {
            supported.emplace_back(row.name, std::move(ops));
        }
    }

    response.return_value_uint16(static_cast<std::uint16_t>(supported.size()));
    for (const auto& [name, ops] : supported)
    {
        response.return_value_data_buffer_out(ToBytes(name));
        AppendOperations(response, ops);
    }
    response.return_success();
    return true;
}

}  // namespace score::crypto::daemon::provider

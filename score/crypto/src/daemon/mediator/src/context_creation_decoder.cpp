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

#include "score/crypto/src/daemon/mediator/src/context_creation_decoder.hpp"

#include "score/crypto/src/daemon/common/context/context_types.hpp"
#include "score/crypto/src/daemon/mediator/context_algorithm.hpp"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"

#include "score/mw/log/logging.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <variant>

namespace score::crypto::daemon::mediator
{

std::optional<common::ProviderTypePreference> DecodeProviderTypePreference(const std::uint8_t wire_value) noexcept
{
    using ProviderType = common::CryptoProviderType;

    switch (wire_value)
    {
        case 0U:
            return common::ProviderTypePreference{ProviderType::DEFAULT, std::nullopt};
        case 1U:
            return common::ProviderTypePreference{ProviderType::HARDWARE, std::nullopt};
        case 2U:
            return common::ProviderTypePreference{ProviderType::SOFTWARE, std::nullopt};
        case 3U:
            return common::ProviderTypePreference{ProviderType::HARDWARE, ProviderType::SOFTWARE};
        case 4U:
            return common::ProviderTypePreference{ProviderType::SOFTWARE, ProviderType::HARDWARE};
        default:
            return std::nullopt;
    }
}

namespace
{

bool IsContextParameterPresent(const control_plane::protocol::SingleOperationRequest& operation,
                               const std::size_t parameter_index) noexcept
{
    return (operation.parameters.size() > parameter_index) &&
           !std::holds_alternative<common::NoParam>(operation.parameters[parameter_index]);
}

}  // namespace

score::crypto::Expected<ContextCreationRequest, score::crypto::CryptoErrorCode> DecodeContextCreationRequest(
    const control_plane::protocol::SingleOperationRequest& operation)
{
    if ((operation.parameters.size() < 2U) || (operation.parameters.size() > operations::CTX_MAX_PARAMETER_COUNT))
    {
        score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Invalid CTX_CREATE parameter count: "
                                   << static_cast<std::uint64_t>(operation.parameters.size());
        return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInvalidArgument);
    }

    auto context_type_res = operation.getParameter<std::string_view>(operations::CTX_PARAM_HANDLER_TYPE);
    if (!context_type_res.has_value())
    {
        score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Wrong parameter type for context_type";
        return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInvalidArgument);
    }
    const auto context_type = context_type_res.value();

    auto algorithm_res = operation.getParameter<std::string_view>(operations::CTX_PARAM_ALGORITHM);
    if (!algorithm_res.has_value())
    {
        score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Wrong parameter type for algorithm";
        return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInvalidArgument);
    }
    const auto algorithm = algorithm_res.value();

    common::ProviderTypePreference provider_preference{common::CryptoProviderType::DEFAULT, std::nullopt};
    if (IsContextParameterPresent(operation, operations::CTX_PARAM_PROVIDER_TYPE))
    {
        const auto provider_type_res = operation.getParameter<std::uint8_t>(operations::CTX_PARAM_PROVIDER_TYPE);
        if (!provider_type_res.has_value())
        {
            score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Wrong parameter type for provider preference";
            return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInvalidArgument);
        }

        const auto decoded_preference = DecodeProviderTypePreference(provider_type_res.value());
        if (!decoded_preference.has_value())
        {
            score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Unknown provider preference value: "
                                       << static_cast<unsigned int>(provider_type_res.value());
            return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInvalidArgument);
        }
        provider_preference = decoded_preference.value();
    }

    // Optional key_node_id parameter (param[3]) for binding a key at context creation.
    std::optional<std::uint64_t> key_node_id{};
    if (IsContextParameterPresent(operation, operations::CTX_PARAM_KEY_NODE_ID))
    {
        const auto key_node_res = operation.getParameter<std::uint64_t>(operations::CTX_PARAM_KEY_NODE_ID);
        if (!key_node_res.has_value())
        {
            score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Wrong parameter type for key resource";
            return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInvalidArgument);
        }
        if (key_node_res.value() == 0U)
        {
            score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Invalid zero key resource identifier";
            return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInvalidArgument);
        }
        key_node_id = key_node_res.value();
    }

    const auto mode = common::ExtractContextMode(operation.parameters);

    // Keyed context families must carry a key reference; operation-mode semantics
    // stay with the concrete handler.
    if (common::RequiredKeyPermission(context_type, mode).has_value() && !key_node_id.has_value())
    {
        score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Missing key resource for keyed context: "
                                   << context_type;
        return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInvalidArgument);
    }

    // Resolve the algorithm name once, before any provider is asked; a name the
    // catalog does not know is refused here. std::nullopt is kept for a
    // KEY:MANAGEMENT context, which is bound to no algorithm.
    std::optional<AlgorithmDescriptor> algorithm_descriptor{};
    if (operations::ContextTakesAlgorithm(context_type))
    {
        algorithm_descriptor = operations::ResolveContextAlgorithm(context_type, algorithm);
        if (!algorithm_descriptor.has_value())
        {
            score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Unknown algorithm: " << algorithm;
            return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kUnsupportedAlgorithm);
        }
    }

    ContextCreationRequest request{};
    request.context_type = context_type;
    request.algorithm = algorithm;
    request.provider = provider_preference;
    request.key_node_id = key_node_id;
    request.mode = mode;
    request.required_capability = common::RequiredProviderCapability(context_type);
    request.algorithm_descriptor = algorithm_descriptor;
    return request;
}

}  // namespace score::crypto::daemon::mediator

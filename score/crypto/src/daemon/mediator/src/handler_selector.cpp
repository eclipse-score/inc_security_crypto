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

#include "score/crypto/src/daemon/mediator/src/handler_selector.hpp"

#include "score/crypto/src/daemon/common/context/i_context_factory.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"

#include "score/mw/log/logging.h"

#include <utility>

namespace score::crypto::daemon::mediator
{

HandlerSelector::HandlerSelector(std::shared_ptr<const ProviderArbiter> arbiter,
                                 std::shared_ptr<const common::ContextFactoryRegistry> context_factories) noexcept
    : m_arbiter(std::move(arbiter)), m_context_factories(std::move(context_factories))
{
}

score::crypto::Expected<HandlerSelection, score::crypto::CryptoErrorCode> HandlerSelector::Select(
    const std::uint64_t client_id,
    const common::ContextCreationRequest& request) const
{
    if (const auto factory = m_context_factories->Find(request.context_type); factory)
    {
        // A factory-served type defines no key permission, so a key reference cannot be authorized.
        if (request.key_node_id.has_value())
        {
            score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Context type " << request.context_type
                                       << " is served by a subsystem and does not accept a key reference";
            return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kKeyOperationNotPermitted);
        }

        auto created = factory->Create(request);
        if (!created.has_value())
        {
            score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Context factory failed for: "
                                       << request.context_type;
            return score::crypto::make_unexpected(common::ToCryptoErrorCode(created.error()));
        }
        return HandlerSelection{std::move(created).value(), nullptr, false};
    }

    auto selection =
        m_arbiter->Select(ProviderSelectionRequest{.client_id = client_id,
                                                   .key_node_id = request.key_node_id,
                                                   .context_type = request.context_type,
                                                   .algorithm = request.algorithm_descriptor,
                                                   .provider_type_preference = request.provider_type_preference,
                                                   .required_capability = request.required_capability});
    if (!selection.has_value())
    {
        score::mw::log::LogError() << "[SCORE_API_MED] ERROR - No compatible provider/handler for: "
                                   << request.context_type << "/" << request.algorithm;
        return score::crypto::make_unexpected(selection.error());
    }

    auto& chosen = selection.value();
    return HandlerSelection{std::move(chosen.handler), std::move(chosen.provider), chosen.used_fallback};
}

}  // namespace score::crypto::daemon::mediator

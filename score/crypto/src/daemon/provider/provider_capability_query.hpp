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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PROVIDER_CAPABILITY_QUERY_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PROVIDER_CAPABILITY_QUERY_HPP

#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/daemon/common/algorithm_catalog.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/provider/i_provider.hpp"
#include "score/crypto/src/daemon/provider/provider_manager.hpp"

#include <array>
#include <memory>
#include <string_view>
#include <vector>

namespace score::crypto::daemon::provider
{

/// @brief Answers the provider and capability queries from the registered providers.
///
/// Serves PROVIDER_INFO, QUERY_CAPABILITIES and SYSTEM_CAPABILITIES. The answers
/// come from the provider manager and from each provider's handler and key
/// factories, so the query holds no state of its own and the mediator only
/// forwards the three operation codes to it.
///
/// Handle() has the shape of a mediator query handler: one instance can serve
/// each code in kOperations.
///
/// Thread-safe as long as the provider manager is.
class ProviderCapabilityQuery
{
  public:
    using Sptr = std::shared_ptr<ProviderCapabilityQuery>;

    /// Operation codes this query serves.
    static const std::array<common::OperationAction, 3U> kOperations;

    /// @param provider_manager Registered providers; may be null, in which case every query is rejected
    ///                         or reports no provider.
    explicit ProviderCapabilityQuery(ProviderManager::Sptr provider_manager);

    /// @brief Whether @p action is one of kOperations.
    [[nodiscard]] static bool Serves(common::OperationAction action) noexcept;

    /// @brief Handle the operation and write its result to the response.
    /// @param request Parent control-plane request (unused; the answers are the same for every client).
    /// @param operation Operation to handle; its action must be one of kOperations.
    /// @param responseBuilder Builder receiving the result or an error.
    /// @return True if the operation succeeded.
    [[nodiscard]] bool Handle(const control_plane::protocol::ControlRequest& request,
                              const control_plane::protocol::SingleOperationRequest& operation,
                              control_plane::protocol::OperationResponseBuilder& responseBuilder) const;

    /// @brief Names of the capability operations at least one of @p providers accepts for @p algorithm.
    ///
    /// In reporting order (HASH, MAC, CIPHER, SIGN, VERIFY, RANDOM, GENERATE_KEY); empty if none.
    [[nodiscard]] static std::vector<std::string_view> CollectCapabilities(
        const std::vector<std::shared_ptr<IProvider>>& providers,
        const ::score::crypto::AlgorithmDescriptor& algorithm);

  private:
    bool HandleProviderInfo(const control_plane::protocol::SingleOperationRequest& operation,
                            control_plane::protocol::OperationResponseBuilder& responseBuilder) const;
    bool HandleQueryCapabilities(const control_plane::protocol::SingleOperationRequest& operation,
                                 control_plane::protocol::OperationResponseBuilder& responseBuilder) const;
    bool HandleSystemCapabilities(const control_plane::protocol::SingleOperationRequest& operation,
                                  control_plane::protocol::OperationResponseBuilder& responseBuilder) const;

    /// Initialized providers, ordered by id.
    [[nodiscard]] std::vector<std::shared_ptr<IProvider>> InitializedProviders() const;

    ProviderManager::Sptr m_provider_manager;
};

}  // namespace score::crypto::daemon::provider

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PROVIDER_CAPABILITY_QUERY_HPP

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

#ifndef SCORE_CRYPTO_SRC_DAEMON_COMMON_CONTEXT_CONTEXT_CREATION_REQUEST_HPP
#define SCORE_CRYPTO_SRC_DAEMON_COMMON_CONTEXT_CONTEXT_CREATION_REQUEST_HPP

#include "score/crypto/src/daemon/common/algorithm_catalog.hpp"
#include "score/crypto/src/daemon/common/context/context_mode.hpp"
#include "score/crypto/src/daemon/common/types.hpp"

#include <cstdint>
#include <optional>
#include <string_view>

namespace score::crypto::daemon::common
{

/// @brief Validated CTX_CREATE request. Views point into the operation's parameters.
struct ContextCreationRequest final
{
    std::string_view context_type;             ///< Context type from the CTX_CREATE request.
    std::string_view algorithm;                ///< Requested algorithm name; may be empty.
    ProviderTypePreference provider_type_preference;  ///< Primary provider type and optional fallback.
    std::optional<std::uint64_t> key_node_id;  ///< Optional key or key-slot node to bind.
    std::optional<ContextMode> mode;           ///< Optional mode used to determine key permission.
    ProviderCapability required_capability{ProviderCapability::kNone};  ///< Capability required by the context scope.
    std::optional<AlgorithmDescriptor> algorithm_descriptor;  ///< Catalog entry, absent when no algorithm is required.
};

}  // namespace score::crypto::daemon::common

#endif  // SCORE_CRYPTO_SRC_DAEMON_COMMON_CONTEXT_CONTEXT_CREATION_REQUEST_HPP

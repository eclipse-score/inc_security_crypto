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

#ifndef SCORE_CRYPTO_SRC_DAEMON_MEDIATOR_CONTEXT_ALGORITHM_HPP
#define SCORE_CRYPTO_SRC_DAEMON_MEDIATOR_CONTEXT_ALGORITHM_HPP

#include "score/crypto/src/daemon/common/algorithm_catalog.hpp"
#include "score/crypto/src/daemon/common/context/context_types.hpp"

#include <optional>
#include <string_view>

namespace score::crypto::daemon::mediator::operations
{

/// @brief Whether a CTX_CREATE context of @p context_type is bound to an algorithm.
///
/// A KEY:MANAGEMENT context names no algorithm; each of its requests carries
/// and resolves its own.
[[nodiscard]] inline constexpr bool ContextTakesAlgorithm(const std::string_view context_type) noexcept
{
    return context_type != common::context_types::kKeyManagement;
}

/// @brief Resolve the algorithm name of a CTX_CREATE request to its catalog row.
///
/// The name is resolved once, here; providers receive the row and never see
/// the name. A RANDOM context without an algorithm asks for the default
/// generator, CTR-DRBG.
/// @return the catalog row, or std::nullopt if the catalog does not know the name.
[[nodiscard]] inline constexpr std::optional<::score::crypto::AlgorithmDescriptor> ResolveContextAlgorithm(
    const std::string_view context_type,
    const std::string_view algorithm) noexcept
{
    if ((context_type == common::context_types::kRandom) && algorithm.empty())
    {
        return ::score::crypto::GetAlgorithmDescriptor(::score::crypto::Algorithm::kCtrDrbg);
    }
    return ::score::crypto::GetAlgorithmDescriptor(algorithm);
}

}  // namespace score::crypto::daemon::mediator::operations

#endif  // SCORE_CRYPTO_SRC_DAEMON_MEDIATOR_CONTEXT_ALGORITHM_HPP

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

#ifndef SCORE_CRYPTO_SRC_API_CONFIG_ALGORITHM_SELECTION_HPP
#define SCORE_CRYPTO_SRC_API_CONFIG_ALGORITHM_SELECTION_HPP

#include "score/crypto/src/api/types/algorithm.hpp"
#include "score/crypto/src/api/types/common.hpp"

#include <string_view>

namespace score
{

namespace crypto
{

namespace config_detail
{

/// @brief Name stored by SetAlgorithm(Algorithm) for a value without a catalog row.
///
/// Deliberately not empty: an empty name selects the default generator of a
/// RANDOM context, whereas this placeholder is refused with
/// CryptoErrorCode::kUnsupportedAlgorithm by every context and key operation.
inline constexpr std::string_view kNoCatalogRowName{"UNKNOWN"};
static_assert(!::score::crypto::FromAlgorithmName(kNoCatalogRowName).has_value(),
              "the placeholder must not name a catalog row");

/// @brief The AlgorithmId that SetAlgorithm(Algorithm) stores: the catalog name of @p algorithm.
[[nodiscard]] inline constexpr AlgorithmId ToAlgorithmId(const Algorithm algorithm) noexcept
{
    const std::string_view name = ::score::crypto::ToAlgorithmName(algorithm);
    return AlgorithmId{name.empty() ? kNoCatalogRowName : name};
}

}  // namespace config_detail

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_SRC_API_CONFIG_ALGORITHM_SELECTION_HPP

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

#ifndef SCORE_CRYPTO_SRC_API_COMMON_SRC_ALGORITHM_CHECK_HPP
#define SCORE_CRYPTO_SRC_API_COMMON_SRC_ALGORITHM_CHECK_HPP

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/types/algorithm.hpp"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"

#include "score/mw/log/logging.h"
#include "score/result/result.h"

#include <string_view>
#include <variant>

namespace score::crypto::api::detail
{

/// @brief Client-side check that an algorithm name is one the daemon can accept.
///
/// The daemon resolves every algorithm name against the catalog and refuses a
/// name without a row with kUnsupportedAlgorithm. The client applies the same
/// rule before any IPC, so an unknown name fails without a daemon round trip
/// and with the same error code. The name is still what goes on the wire.
///
/// @param operation Caller name, for the log message only.
/// @return std::monostate if the catalog knows @p name, else kUnsupportedAlgorithm.
[[nodiscard]] inline score::Result<std::monostate> CheckAlgorithmName(const std::string_view name,
                                                                      const std::string_view operation) noexcept
{
    if (::score::crypto::FromAlgorithmName(name).has_value())
    {
        return std::monostate{};
    }
    score::mw::log::LogError() << "[API]" << operation << "ERROR: unknown algorithm '" << name << "'";
    return score::Result<std::monostate>{score::unexpect,
                                         MakeError(CryptoErrorCode::kUnsupportedAlgorithm, "unknown algorithm")};
}

/// @brief CheckAlgorithmName() for the algorithm of a CTX_CREATE request.
///
/// Uses the daemon's own context rules (mediator_operations.hpp): a context
/// type bound to no algorithm (KEY_MANAGEMENT) is not checked, and a RANDOM
/// context with an empty algorithm stands for CTR-DRBG and is accepted.
[[nodiscard]] inline score::Result<std::monostate> CheckContextAlgorithm(const std::string_view context_type,
                                                                         const std::string_view name,
                                                                         const std::string_view operation) noexcept
{
    namespace med_ops = ::score::crypto::daemon::mediator::operations;
    if (!med_ops::ContextTakesAlgorithm(context_type))
    {
        return std::monostate{};
    }
    const auto row = med_ops::ResolveContextAlgorithm(context_type, name);
    return CheckAlgorithmName(row.has_value() ? row->name : name, operation);
}

}  // namespace score::crypto::api::detail

#endif  // SCORE_CRYPTO_SRC_API_COMMON_SRC_ALGORITHM_CHECK_HPP

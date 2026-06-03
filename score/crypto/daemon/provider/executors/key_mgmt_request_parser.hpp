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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_EXECUTORS_KEY_MGMT_REQUEST_PARSER_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_EXECUTORS_KEY_MGMT_REQUEST_PARSER_HPP

#include "score/crypto/daemon/common/daemon_error.hpp"
#include "score/crypto/daemon/common/types.hpp"
#include "score/crypto/daemon/key_management/interfaces/key_types.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

namespace score::crypto::daemon::provider::crypto_executor
{
namespace key_mgmt_request_parser
{

/// Extract a uint64 parameter at the given index.
///
/// @return The extracted value, or ERROR_INSUFFICIENT_PARAMETERS / ERROR_INVALID_PARAMETER.
[[nodiscard]] inline Expected<std::uint64_t, score::crypto::daemon::common::DaemonErrorCode> ExtractUint64(
    const common::RequestParameters& request,
    std::size_t index)
{
    if (request.size() <= index)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInsufficientParameters);
    }
    const auto* val = std::get_if<std::uint64_t>(&request[index]);
    if (val == nullptr)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }
    return *val;
}

/// Extract a non-empty string_view parameter at the given index.
///
/// @return The extracted view, or ERROR_INSUFFICIENT_PARAMETERS / ERROR_INVALID_PARAMETER.
[[nodiscard]] inline Expected<std::string_view, score::crypto::daemon::common::DaemonErrorCode> ExtractAlgorithm(
    const common::RequestParameters& request,
    std::size_t index)
{
    if (request.size() <= index)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInsufficientParameters);
    }
    const auto* val = std::get_if<std::string_view>(&request[index]);
    if ((val == nullptr) || val->empty())
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }
    return *val;
}

/// Try to extract an optional uint64 permission value at the given index.
///
/// Returns std::nullopt when the index is out of range or the variant
/// alternative does not hold a uint64_t (both are silently acceptable).
[[nodiscard]] inline std::optional<std::uint64_t> ExtractOptionalPermissions(const common::RequestParameters& request,
                                                                             std::size_t index)
{
    if (request.size() <= index)
    {
        return std::nullopt;
    }
    const auto* val = std::get_if<std::uint64_t>(&request[index]);
    if (val == nullptr)
    {
        return std::nullopt;
    }

    return *val;
}

/// Build a KeyGenerationRequest from the packed request parameters.
///
/// Expected layout:
///   request[0] = algorithm    (string_view, required)
///   request[1] = permissions  (uint64_t,    optional)
[[nodiscard]] inline Expected<key_management::KeyGenerationRequest, score::crypto::daemon::common::DaemonErrorCode>
BuildGenerationRequest(const common::RequestParameters& request)
{
    auto algo = ExtractAlgorithm(request, 0U);
    if (!algo.has_value())
    {
        return score::crypto::make_unexpected(algo.error());
    }

    key_management::KeyGenerationRequest req{};
    req.algorithm = std::string(algo.value());

    const auto perm = ExtractOptionalPermissions(request, 1U);
    if (perm.has_value())
    {
        req.permissions = static_cast<score::mw::crypto::KeyOperationPermission>(perm.value());
    }

    return req;
}

}  // namespace key_mgmt_request_parser
}  // namespace score::crypto::daemon::provider::crypto_executor

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_EXECUTORS_KEY_MGMT_REQUEST_PARSER_HPP

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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_EXECUTORS_KEY_MGMT_REQUEST_PARSER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_EXECUTORS_KEY_MGMT_REQUEST_PARSER_HPP

#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_types.hpp"

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

/// Try to extract an optional permission bitmask at the given index.
///
/// KeyOperationPermission is a uint32_t enum and the API serialises it with
/// with_in_val_uint32(), so uint32_t is the alternative to look for. The
/// variant keeps uint32_t and uint64_t distinct and the flatbuffers transport
/// preserves that distinction, so reading the wrong width yields nullopt —
/// silently downgrading a restricted key to the kAll default.
///
/// Returns std::nullopt when the index is out of range or the parameter is not
/// a uint32_t (both mean "caller did not specify permissions").
[[nodiscard]] inline std::optional<score::crypto::KeyOperationPermission> ExtractOptionalPermissions(
    const common::RequestParameters& request,
    std::size_t index)
{
    if (request.size() <= index)
    {
        return std::nullopt;
    }
    const auto* val = std::get_if<std::uint32_t>(&request[index]);
    if (val == nullptr)
    {
        return std::nullopt;
    }

    return static_cast<score::crypto::KeyOperationPermission>(*val);
}

/// Build a KeyGenerationRequest from the packed request parameters.
///
/// Expected layout:
///   request[0] = algorithm              (string_view, required)
///   request[1] = permissions            (uint32_t,    optional)
///   request[2] = public_key_permissions (uint32_t,    optional, asymmetric only)
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
        req.permissions = perm.value();
    }

    // Left as nullopt when absent, which the key factory reads as "public half
    // unrestricted" — the contract documented on GenerateKeyParams. The public
    // half of a key pair is public information, so withholding kVerify/kEncrypt
    // by default would cost compatibility without buying confidentiality.
    req.public_key_permissions = ExtractOptionalPermissions(request, 2U);

    return req;
}

}  // namespace key_mgmt_request_parser
}  // namespace score::crypto::daemon::provider::crypto_executor

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_EXECUTORS_KEY_MGMT_REQUEST_PARSER_HPP

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

#ifndef SCORE_CRYPTO_SRC_DAEMON_COMMON_CONTEXT_TYPES_HPP
#define SCORE_CRYPTO_SRC_DAEMON_COMMON_CONTEXT_TYPES_HPP

#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/api/types/key.hpp"
#include "score/crypto/src/daemon/common/context_mode.hpp"

#include <cstdint>
#include <optional>
#include <string_view>

namespace score::crypto::daemon::common
{

/// @brief Canonical context-type identifiers sent as CTX_CREATE param[0].
///
/// The client writes these, the mediator dispatches on them, and every provider
/// handler factory keys its lookup table off them — so they live here rather
/// than being spelled out as literals in each of those places.
namespace context_types
{
inline constexpr std::string_view kHash = "HASH";
inline constexpr std::string_view kMac = "MAC";
inline constexpr std::string_view kCipher = "CIPHER";
inline constexpr std::string_view kSign = "SIGN";
inline constexpr std::string_view kVerify = "VERIFY";
inline constexpr std::string_view kRandom = "RANDOM";
inline constexpr std::string_view kKem = "KEM";
inline constexpr std::string_view kKeyManagement = "KEY_MANAGEMENT";
}  // namespace context_types

/// @brief The key permission a context of this type consumes for its whole lifetime.
///
/// A context is bound to one key and one direction at CTX_CREATE and cannot
/// change either afterwards, so the permission it needs is fully determined
/// here. That makes context creation the right place to enforce it: the check
/// happens once, and no later operation on the context can escape it.
///
/// @param context_type CTX_CREATE param[0].
/// @param mode         CTX_CREATE param[4], decoded with ExtractContextMode().
///
/// @return The required permission, or std::nullopt when the context type
///         consumes no key permission:
///           - HASH and RANDOM bind no key at all.
///           - KEM uses the key-agreement permission for encapsulation and
///             decapsulation.
///           - KEY_MANAGEMENT binds no key at CTX_CREATE; its operations carry
///             their own key references and are checked individually (kDerive
///             for DeriveKey, kWrap for WrapKey, kExport for ExportKey).
///         std::nullopt is also the answer for a context type this build does
///         not recognise. A caller that holds a key treats both the same way:
///         there is no permission to check against, so the key is not bound.
[[nodiscard]] inline constexpr std::optional<score::crypto::KeyOperationPermission> RequiredKeyPermission(
    std::string_view context_type,
    std::optional<ContextMode> mode) noexcept
{
    using Permission = score::crypto::KeyOperationPermission;

    if (context_type == context_types::kMac)
    {
        // One permission covers both directions: verifying a MAC means
        // recomputing it, so a key that can verify can also generate.
        return Permission::kMac;
    }
    if (context_type == context_types::kSign)
    {
        return Permission::kSign;
    }
    if (context_type == context_types::kVerify)
    {
        return Permission::kVerify;
    }
    if (context_type == context_types::kKem)
    {
        return Permission::kAgree;
    }
    if (context_type == context_types::kCipher)
    {
        if (mode == ContextMode::kEncrypt)
        {
            return Permission::kEncrypt;
        }
        if (mode == ContextMode::kDecrypt)
        {
            return Permission::kDecrypt;
        }
        // A cipher context must say which direction it wants. A missing mode,
        // or one from the MAC/signature vocabulary, is a malformed request;
        // demanding both bits fails closed, so a key granted only one direction
        // cannot slip through on a request that did not say which it wanted.
        return Permission::kEncrypt | Permission::kDecrypt;
    }

    return std::nullopt;
}

}  // namespace score::crypto::daemon::common

#endif  // SCORE_CRYPTO_SRC_DAEMON_COMMON_CONTEXT_TYPES_HPP

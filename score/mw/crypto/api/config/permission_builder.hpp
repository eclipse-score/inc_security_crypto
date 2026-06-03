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

#ifndef SCORE_MW_CRYPTO_API_CONFIG_PERMISSION_BUILDER_HPP
#define SCORE_MW_CRYPTO_API_CONFIG_PERMISSION_BUILDER_HPP

#include "score/mw/crypto/api/common/types.hpp"

namespace score
{
namespace mw
{
namespace crypto
{

/// Fluent builder for constructing @c KeyOperationPermission bitmasks.
///
/// Usage:
/// @code
///   auto perms = PermissionBuilder()
///       .AllowEncrypt()
///       .AllowDecrypt()
///       .AllowExport()
///       .Build();
/// @endcode
///
/// The builder starts with kNone and accumulates bits via each Allow*() call.
class PermissionBuilder final
{
  public:
    constexpr PermissionBuilder() noexcept = default;

    /// Start from an existing permission set.
    constexpr explicit PermissionBuilder(KeyOperationPermission initial) noexcept
        : m_perms{static_cast<uint32_t>(initial)}
    {
    }

    // -- Individual permission setters --

    constexpr PermissionBuilder& AllowEncrypt() noexcept
    {
        m_perms |= static_cast<uint32_t>(KeyOperationPermission::kEncrypt);
        return *this;
    }
    constexpr PermissionBuilder& AllowDecrypt() noexcept
    {
        m_perms |= static_cast<uint32_t>(KeyOperationPermission::kDecrypt);
        return *this;
    }
    constexpr PermissionBuilder& AllowWrap() noexcept
    {
        m_perms |= static_cast<uint32_t>(KeyOperationPermission::kWrap);
        return *this;
    }
    constexpr PermissionBuilder& AllowUnwrap() noexcept
    {
        m_perms |= static_cast<uint32_t>(KeyOperationPermission::kUnwrap);
        return *this;
    }
    constexpr PermissionBuilder& AllowSign() noexcept
    {
        m_perms |= static_cast<uint32_t>(KeyOperationPermission::kSign);
        return *this;
    }
    constexpr PermissionBuilder& AllowVerify() noexcept
    {
        m_perms |= static_cast<uint32_t>(KeyOperationPermission::kVerify);
        return *this;
    }
    constexpr PermissionBuilder& AllowMac() noexcept
    {
        m_perms |= static_cast<uint32_t>(KeyOperationPermission::kMac);
        return *this;
    }
    constexpr PermissionBuilder& AllowAgree() noexcept
    {
        m_perms |= static_cast<uint32_t>(KeyOperationPermission::kAgree);
        return *this;
    }
    constexpr PermissionBuilder& AllowDerive() noexcept
    {
        m_perms |= static_cast<uint32_t>(KeyOperationPermission::kDerive);
        return *this;
    }
    constexpr PermissionBuilder& AllowExport() noexcept
    {
        m_perms |= static_cast<uint32_t>(KeyOperationPermission::kExport);
        return *this;
    }
    constexpr PermissionBuilder& AllowImport() noexcept
    {
        m_perms |= static_cast<uint32_t>(KeyOperationPermission::kImport);
        return *this;
    }

    // -- Composite setters --

    constexpr PermissionBuilder& AllowDataProtection() noexcept
    {
        m_perms |= static_cast<uint32_t>(KeyOperationPermission::kDataProtection);
        return *this;
    }
    constexpr PermissionBuilder& AllowAuthentication() noexcept
    {
        m_perms |= static_cast<uint32_t>(KeyOperationPermission::kAuthentication);
        return *this;
    }
    constexpr PermissionBuilder& AllowAll() noexcept
    {
        m_perms = static_cast<uint32_t>(KeyOperationPermission::kAll);
        return *this;
    }

    // -- Removal --

    constexpr PermissionBuilder& Deny(KeyOperationPermission perm) noexcept
    {
        m_perms &= ~static_cast<uint32_t>(perm);
        return *this;
    }

    // -- Terminal --

    [[nodiscard]] constexpr KeyOperationPermission Build() const noexcept
    {
        return static_cast<KeyOperationPermission>(m_perms);
    }

    /// Implicit conversion for use as a direct argument.
    [[nodiscard]] constexpr operator KeyOperationPermission() const noexcept  // NOLINT
    {
        return static_cast<KeyOperationPermission>(m_perms);
    }

  private:
    uint32_t m_perms{0U};
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_CONFIG_PERMISSION_BUILDER_HPP

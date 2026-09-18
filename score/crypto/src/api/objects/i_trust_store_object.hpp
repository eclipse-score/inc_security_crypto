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

#ifndef SCORE_CRYPTO_SRC_API_OBJECTS_I_TRUST_STORE_OBJECT_HPP
#define SCORE_CRYPTO_SRC_API_OBJECTS_I_TRUST_STORE_OBJECT_HPP

#include "score/crypto/src/api/objects/i_crypto_object.hpp"
#include "score/crypto/src/api/types/certificate.hpp"
#include "score/span.hpp"

#include <cstdint>
#include <memory>
#include <vector>

namespace score
{

namespace crypto
{

/// @brief Read-only typed view of a named trust store.
///
/// Provides a point-in-time snapshot of trust store membership: which certificates
/// are present, their membership kind, and their enabled/disabled state.
///
/// Mutations (add, remove, enable, disable, import CRL) are performed via
/// ITrustStoreManagementContext — not through this object.
///
/// Obtained via ICryptoContext::GetTrustStoreObject().
class ITrustStoreObject : public ICryptoObject
{
  public:
    using Uptr = std::unique_ptr<ITrustStoreObject>;

    ~ITrustStoreObject() override = default;

    ITrustStoreObject(const ITrustStoreObject&) = delete;
    ITrustStoreObject& operator=(const ITrustStoreObject&) = delete;
    ITrustStoreObject(ITrustStoreObject&&) = default;
    ITrustStoreObject& operator=(ITrustStoreObject&&) = default;

    /// @brief Returns the point-in-time snapshot of all occupied trust store members.
    ///
    /// Each entry corresponds to a certificate slot that currently holds a certificate.
    /// Empty slots (not yet populated) are omitted.
    virtual const std::vector<MemberInfo>& GetMembers() const noexcept = 0;

    // ---- Convenience accessors (defined in terms of GetMembers()) ----

    /// @brief Find the member entry for a given slot resource ID.
    ///
    /// Matches by id and type only — primary_provider is not compared because
    /// MemberInfo slot_id has primary_provider=0 as a placeholder.
    /// @returns Pointer to the matching MemberInfo, or nullptr if not a member.
    [[nodiscard]] virtual const MemberInfo* FindMember(const CryptoResourceId& slot) const noexcept = 0;

    /// @brief Find the member with the given SHA-256 fingerprint.
    ///
    /// @param fingerprint 32-byte fingerprint span. Returns nullptr if its size is not 32.
    /// @returns Pointer to the matching MemberInfo, or nullptr if not found.
    [[nodiscard]] virtual const MemberInfo* FindMemberByFingerprint(
        score::cpp::span<const uint8_t> fingerprint) const noexcept = 0;

    /// @brief Returns the slot IDs of all enabled trust store members.
    [[nodiscard]] virtual std::vector<CryptoResourceId> GetEnabledMemberSlotIds() const = 0;

    /// @brief Returns the slot IDs of all disabled trust store members.
    [[nodiscard]] virtual std::vector<CryptoResourceId> GetDisabledMemberSlotIds() const = 0;

  protected:
    ITrustStoreObject() = default;
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_SRC_API_OBJECTS_I_TRUST_STORE_OBJECT_HPP

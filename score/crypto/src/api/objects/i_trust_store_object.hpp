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

#include "score/crypto/src/api/common/types.hpp"
#include "score/crypto/src/api/objects/i_crypto_object.hpp"
#include "score/span.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <string>
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
/// ICertificateManagementContext — not through this object.
///
/// Obtained via ICryptoContext::GetTrustStoreObject().
class ITrustStoreObject : public ICryptoObject
{
  public:
    static constexpr std::size_t kSha256FingerprintSize = 32U;

    using Uptr = std::unique_ptr<ITrustStoreObject>;

    /// @brief Membership kind of a trust store anchor.
    enum class MemberKind : uint8_t
    {
        kSharedStatic = 0U,        ///< Externally managed slot; read-only from trust store perspective.
        kExclusiveMutable = 1U,    ///< Trust-store-owned exclusive slot; mutable via management context.
        kConditionalExternal = 2U  ///< External slot; disabled after unexpected content change.
    };

    /// @brief Snapshot of a single trust store member.
    ///
    /// Both slot_id and sha256_fingerprint are provided so callers can:
    /// - Use slot_id directly for enable/disable/importCrl operations without a round-trip.
    /// - Use sha256_fingerprint for quick identity matching against externally known fingerprints
    ///   (e.g., from a security bulletin) without loading the full certificate.
    /// - Use subject + issuer + serial_number for human-readable identification and logging.
    struct MemberInfo
    {
        CryptoResourceId slot_id{};  ///< kCertSlot resource — use for management ops.
        std::array<uint8_t, kSha256FingerprintSize>
            sha256_fingerprint{};                    ///< SHA-256 fingerprint of the member certificate.
        std::string subject;                         ///< RFC 4514 Subject DN (e.g., "CN=Root CA,O=ACME,C=DE").
        std::string issuer;                          ///< RFC 4514 Issuer DN.
        std::string serial_number;                   ///< Uppercase hex serial (e.g., "01ABCDEF").
        MemberKind kind{MemberKind::kSharedStatic};  ///< Membership type.
        bool is_enabled{true};                       ///< Whether anchor is active for chain building.
    };

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

    // ---- Non-virtual convenience accessors (operate on GetMembers() locally) ----

    /// @brief Find the member entry for a given slot resource ID.
    ///
    /// Matches by id and type only — primary_provider is not compared because
    /// MemberInfo slot_id has primary_provider=0 as a placeholder.
    /// @returns Pointer to the matching MemberInfo, or nullptr if not a member.
    [[nodiscard]] const MemberInfo* FindMember(const CryptoResourceId& slot) const noexcept
    {
        for (const auto& member : GetMembers())
        {
            if (member.slot_id.id == slot.id && member.slot_id.type == slot.type)
            {
                return &member;
            }
        }
        return nullptr;
    }

    /// @brief Find the member with the given SHA-256 fingerprint.
    ///
    /// @param fingerprint 32-byte fingerprint span. Returns nullptr if its size is not 32.
    /// @returns Pointer to the matching MemberInfo, or nullptr if not found.
    [[nodiscard]] const MemberInfo* FindMemberByFingerprint(score::cpp::span<const uint8_t> fingerprint) const noexcept
    {
        if (fingerprint.size() != kSha256FingerprintSize)
        {
            return nullptr;
        }
        for (const auto& member : GetMembers())
        {
            if (std::equal(fingerprint.begin(), fingerprint.end(), member.sha256_fingerprint.begin()))
            {
                return &member;
            }
        }
        return nullptr;
    }

    /// @brief Returns the slot IDs of all enabled trust store members.
    [[nodiscard]] std::vector<CryptoResourceId> GetEnabledMemberSlotIds() const
    {
        std::vector<CryptoResourceId> result;
        for (const auto& member : GetMembers())
        {
            if (member.is_enabled)
            {
                result.push_back(member.slot_id);
            }
        }
        return result;
    }

    /// @brief Returns the slot IDs of all disabled trust store members.
    [[nodiscard]] std::vector<CryptoResourceId> GetDisabledMemberSlotIds() const
    {
        std::vector<CryptoResourceId> result;
        for (const auto& member : GetMembers())
        {
            if (!member.is_enabled)
            {
                result.push_back(member.slot_id);
            }
        }
        return result;
    }

  protected:
    ITrustStoreObject() = default;
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_SRC_API_OBJECTS_I_TRUST_STORE_OBJECT_HPP

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

#include "score/crypto/src/api/objects/src/trust_store_object_impl.hpp"

#include <algorithm>
#include <utility>

namespace score
{

namespace crypto
{

TrustStoreObjectImpl::TrustStoreObjectImpl(CryptoResourceId id, std::vector<MemberInfo> members)
    : m_id(id), m_members(std::move(members))
{
}

CryptoResourceId TrustStoreObjectImpl::GetId() const noexcept
{
    return m_id;
}

ResourceType TrustStoreObjectImpl::GetType() const noexcept
{
    return ResourceType::kCertificateTrustStore;
}

const std::vector<MemberInfo>& TrustStoreObjectImpl::GetMembers() const noexcept
{
    return m_members;
}

const MemberInfo* TrustStoreObjectImpl::FindMember(const CryptoResourceId& slot) const noexcept
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

const MemberInfo* TrustStoreObjectImpl::FindMemberByFingerprint(
    score::cpp::span<const uint8_t> fingerprint) const noexcept
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

std::vector<CryptoResourceId> TrustStoreObjectImpl::GetEnabledMemberSlotIds() const
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

std::vector<CryptoResourceId> TrustStoreObjectImpl::GetDisabledMemberSlotIds() const
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

}  // namespace crypto

}  // namespace score

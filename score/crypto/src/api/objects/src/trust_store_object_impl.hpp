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

#ifndef SCORE_CRYPTO_SRC_API_OBJECTS_SRC_TRUST_STORE_OBJECT_IMPL_HPP
#define SCORE_CRYPTO_SRC_API_OBJECTS_SRC_TRUST_STORE_OBJECT_IMPL_HPP

#include "score/crypto/src/api/objects/i_trust_store_object.hpp"
#include "score/crypto/src/api/types/certificate.hpp"
#include "score/span.hpp"

#include <cstdint>
#include <vector>

namespace score
{

namespace crypto
{

/// @brief Concrete ITrustStoreObject holding a point-in-time member snapshot.
///
/// Constructed by ICryptoContext::GetTrustStoreObject() after a TRUST_STORE_GET_INFO
/// round-trip. Immutable after construction — no IPC is sent on destruction.
class TrustStoreObjectImpl final : public ITrustStoreObject
{
  public:
    TrustStoreObjectImpl(CryptoResourceId id, std::vector<MemberInfo> members);
    ~TrustStoreObjectImpl() override = default;

    TrustStoreObjectImpl(const TrustStoreObjectImpl&) = delete;
    TrustStoreObjectImpl& operator=(const TrustStoreObjectImpl&) = delete;
    TrustStoreObjectImpl(TrustStoreObjectImpl&&) = delete;
    TrustStoreObjectImpl& operator=(TrustStoreObjectImpl&&) = delete;

    CryptoResourceId GetId() const noexcept override;
    ResourceType GetType() const noexcept override;
    const std::vector<MemberInfo>& GetMembers() const noexcept override;

    const MemberInfo* FindMember(const CryptoResourceId& slot) const noexcept override;
    const MemberInfo* FindMemberByFingerprint(score::cpp::span<const uint8_t> fingerprint) const noexcept override;
    std::vector<CryptoResourceId> GetEnabledMemberSlotIds() const override;
    std::vector<CryptoResourceId> GetDisabledMemberSlotIds() const override;

  private:
    CryptoResourceId m_id;
    std::vector<MemberInfo> m_members;
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_SRC_API_OBJECTS_SRC_TRUST_STORE_OBJECT_IMPL_HPP

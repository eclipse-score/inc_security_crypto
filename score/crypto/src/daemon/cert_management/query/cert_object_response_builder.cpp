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

#include "score/crypto/src/daemon/cert_management/query/cert_object_response_builder.hpp"
#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/daemon/cert_management/core/cert_management_service.hpp"

#include <cstdint>
#include <utility>

namespace score::crypto::daemon::cert_management::query
{

namespace
{

/// Rejects a built payload that exceeds the IPC response budget instead of
/// returning it. Centralises the check so every builder below applies the
/// same conservative margin.
score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> CheckBudget(
    common::ResponseParameters params)
{
    if (common::EstimateResponseSize(params) > common::kMaxResponsePayloadBytes)
        return score::crypto::make_unexpected(common::DaemonErrorCode::kResponseTooLarge);
    return params;
}

score::crypto::Expected<score::crypto::MemberKind, common::DaemonErrorCode> ToApiMemberKind(TrustStoreMemberKind kind)
{
    switch (kind)
    {
        case TrustStoreMemberKind::kSharedStatic:
            return score::crypto::MemberKind::kSharedStatic;
        case TrustStoreMemberKind::kExclusiveMutable:
            return score::crypto::MemberKind::kExclusiveMutable;
        case TrustStoreMemberKind::kConditionalExternal:
            return score::crypto::MemberKind::kConditionalExternal;
    }
    return score::crypto::make_unexpected(common::DaemonErrorCode::kInvalidArgument);
}

}  // namespace

score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> BuildCertObjectResponse(
    const CertObject& cert,
    std::optional<score::crypto::CrlMetadata> crl_metadata)
{
    const auto& meta = cert.GetChainMetadata();
    common::ResponseParameters out;
    out.push_back(common::OwnedString{meta.subject_canonical});
    out.push_back(common::OwnedString{meta.issuer_canonical});
    out.push_back(static_cast<std::uint64_t>(meta.not_before_epoch_s));
    out.push_back(static_cast<std::uint64_t>(meta.not_after_epoch_s));
    out.push_back(static_cast<std::uint8_t>(meta.is_ca ? 1U : 0U));
    out.push_back(common::OwnedBuffer{meta.skid.begin(), meta.skid.end()});
    out.push_back(common::OwnedBuffer{meta.akid.begin(), meta.akid.end()});
    out.push_back(common::OwnedString{meta.serial_number_hex});
    out.push_back(common::OwnedBuffer{meta.fingerprint.begin(), meta.fingerprint.end()});
    out.push_back(static_cast<std::uint8_t>(crl_metadata.has_value() ? 1U : 0U));
    const auto crl = crl_metadata.value_or(score::crypto::CrlMetadata{});
    out.push_back(common::OwnedBuffer{crl.fingerprint.begin(), crl.fingerprint.end()});
    out.push_back(common::OwnedBuffer{crl.issuer_fingerprint.begin(), crl.issuer_fingerprint.end()});
    out.push_back(static_cast<std::uint64_t>(crl.this_update));
    out.push_back(static_cast<std::uint64_t>(crl.next_update));
    out.push_back(crl.crl_number);
    return CheckBudget(std::move(out));
}

score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode>
BuildCertSlotInfoResponse(CertSlotManager& mgr, CertSlotHandle slot, data_manager::ClientId client_id)
{
    auto info_res = mgr.GetSlotInfo(slot, client_id);
    if (!info_res.has_value())
        return score::crypto::make_unexpected(info_res.error());

    const bool has_crl = info_res.value().has_crl;
    common::ResponseParameters out;
    out.push_back(static_cast<std::uint8_t>(info_res.value().state));
    out.push_back(static_cast<std::uint8_t>(has_crl ? 1U : 0U));
    return out;
}

score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> BuildTrustStoreMemberIdListResponse(
    const std::vector<CertSlotHandle>& slots,
    CertManagementService& service,
    std::uint64_t client_id)
{
    std::vector<std::uint64_t> slot_node_ids;
    slot_node_ids.reserve(slots.size());
    for (const auto& slot : slots)
    {
        auto nid_res = service.ResolveCertSlot(slot, client_id);
        if (!nid_res.has_value())
            continue;  // slot not resolvable — omit silently rather than failing
        slot_node_ids.push_back(static_cast<std::uint64_t>(nid_res.value()));
    }

    common::ResponseParameters out;
    out.push_back(static_cast<std::uint64_t>(slot_node_ids.size()));
    for (const auto node_id : slot_node_ids)
        out.push_back(node_id);
    return CheckBudget(std::move(out));
}

score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> BuildTrustStoreMemberObjectResponse(
    const TrustStoreManager::MemberSnapshot& member,
    CertManagementService& service,
    std::uint64_t client_id)
{
    auto nid_res = service.ResolveCertSlot(member.slot_handle, client_id);
    if (!nid_res.has_value())
        return score::crypto::make_unexpected(nid_res.error());
    const auto kind_res = ToApiMemberKind(member.kind);
    if (!kind_res.has_value())
        return score::crypto::make_unexpected(kind_res.error());

    common::ResponseParameters out;
    out.push_back(static_cast<std::uint64_t>(nid_res.value()));
    out.push_back(common::OwnedBuffer{member.fingerprint.begin(), member.fingerprint.end()});
    out.push_back(common::OwnedString{member.subject});
    out.push_back(common::OwnedString{member.issuer});
    out.push_back(common::OwnedString{member.serial_number});
    out.push_back(static_cast<std::uint8_t>(kind_res.value()));
    out.push_back(static_cast<std::uint8_t>(member.status));
    return CheckBudget(std::move(out));
}

}  // namespace score::crypto::daemon::cert_management::query

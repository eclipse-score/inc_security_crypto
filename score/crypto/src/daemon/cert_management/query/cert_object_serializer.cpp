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

#include "score/crypto/src/daemon/cert_management/query/cert_object_serializer.hpp"
#include "score/crypto/src/daemon/cert_management/core/cert_management_service.hpp"

#include <cstdint>

namespace score::crypto::daemon::cert_management::query
{

common::ResponseParameters SerializeCertObject(const CertObject& cert)
{
    const auto& meta = cert.GetChainMetadata();
    common::ResponseParameters out;
    out.push_back(common::OwnedString{meta.subject_canonical});
    out.push_back(common::OwnedString{meta.issuer_canonical});
    out.push_back(static_cast<std::uint64_t>(static_cast<uint64_t>(meta.not_before_epoch_s)));
    out.push_back(static_cast<std::uint64_t>(static_cast<uint64_t>(meta.not_after_epoch_s)));
    out.push_back(static_cast<std::uint8_t>(meta.is_ca ? 1U : 0U));
    out.push_back(common::OwnedBuffer{meta.skid.begin(), meta.skid.end()});
    out.push_back(common::OwnedBuffer{meta.akid.begin(), meta.akid.end()});
    out.push_back(common::OwnedString{meta.serial_number_hex});
    out.push_back(common::OwnedBuffer{meta.fingerprint.begin(), meta.fingerprint.end()});
    return out;
}

score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> SerializeCertSlotInfo(
    ICertSlotHandler& handler,
    const CertSlotConfig& config)
{
    auto info_res = handler.GetSlotInfo(config);
    if (!info_res.has_value())
        return score::crypto::make_unexpected(info_res.error());

    const bool has_crl = handler.HasCrl(config);
    int64_t crl_next = 0;
    if (has_crl)
    {
        auto nu = handler.GetCrlNextUpdate(config);
        if (nu.has_value())
            crl_next = nu.value();
    }

    common::ResponseParameters out;
    out.push_back(static_cast<std::uint8_t>(info_res.value().state));
    out.push_back(static_cast<std::uint8_t>(has_crl ? 1U : 0U));
    out.push_back(static_cast<std::uint64_t>(static_cast<uint64_t>(crl_next)));
    return out;
}

common::ResponseParameters SerializeTrustStoreMembers(const std::vector<TrustStoreManager::MemberSnapshot>& snapshot,
                                                      CertManagementService& service,
                                                      std::uint64_t client_id)
{
    struct ResolvedEntry
    {
        std::uint64_t slot_node_id;
        const TrustStoreManager::MemberSnapshot* snap;
    };
    std::vector<ResolvedEntry> entries;
    entries.reserve(snapshot.size());
    for (const auto& member : snapshot)
    {
        auto nid_res = service.ResolveCertSlot(member.slot_name, client_id);
        if (!nid_res.has_value())
            continue;  // slot not resolvable — omit silently rather than failing
        entries.push_back({static_cast<std::uint64_t>(nid_res.value()), &member});
    }

    common::ResponseParameters out;
    out.push_back(static_cast<std::uint64_t>(entries.size()));
    for (const auto& entry : entries)
    {
        out.push_back(entry.slot_node_id);
        out.push_back(common::OwnedBuffer{entry.snap->fingerprint.begin(), entry.snap->fingerprint.end()});
        out.push_back(common::OwnedString{entry.snap->subject});
        out.push_back(common::OwnedString{entry.snap->issuer});
        out.push_back(common::OwnedString{entry.snap->serial_number});
        out.push_back(static_cast<std::uint8_t>(static_cast<uint8_t>(entry.snap->kind)));
        out.push_back(static_cast<std::uint8_t>(entry.snap->is_enabled ? 1U : 0U));
    }
    return out;
}

}  // namespace score::crypto::daemon::cert_management::query

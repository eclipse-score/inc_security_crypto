/*******************************************************************************
 *
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
 *******************************************************************************
 */

#include "score/crypto/src/daemon/cert_management/context/verification/request_builder.hpp"

#include "score/crypto/src/daemon/cert_management/interfaces/i_trust_store_handler.hpp"
#include "score/mw/log/logging.h"

#include <algorithm>
#include <string_view>
#include <utility>

namespace score::crypto::daemon::cert_management
{

namespace
{

constexpr std::string_view kLogPrefix{"[CERT_VERIFY_REQ] "};

bool SameCertificate(const CertObject& first, const CertObject& second)
{
    const auto first_fingerprint = first.GetFingerprint();
    const auto second_fingerprint = second.GetFingerprint();
    return first_fingerprint.size() == second_fingerprint.size() &&
           std::equal(first_fingerprint.begin(), first_fingerprint.end(), second_fingerprint.begin());
}

bool Contains(const std::vector<CertObject::Sptr>& certificates, const CertObject& certificate)
{
    return std::any_of(certificates.begin(), certificates.end(), [&certificate](const CertObject::Sptr& candidate) {
        return SameCertificate(*candidate, certificate);
    });
}

/// Append @p certificate unless it is absent or a certificate with the same fingerprint is already listed.
void AppendUnique(std::vector<CertObject::Sptr>& certificates, const CertObject::Sptr& certificate)
{
    if (certificate && !Contains(certificates, *certificate))
    {
        certificates.push_back(certificate);
    }
}

/// Append a CRL snapshot unless it is absent or already listed. A CRL without a nextUpdate has no expiry bound, so it
/// is not offered as revocation evidence; it is logged and left out.
void AppendUsableCrl(std::vector<CrlData::Sptrc>& crls, const CrlData::Sptrc& crl)
{
    if (!crl || std::find(crls.begin(), crls.end(), crl) != crls.end())
    {
        return;
    }
    if (!crl->metadata.has_value() || crl->metadata->next_update == 0)
    {
        score::mw::log::LogWarn() << kLogPrefix << "A CRL without a nextUpdate is not used for revocation";
        return;
    }
    crls.push_back(crl);
}

}  // namespace

VerificationRequestBuilder::VerificationRequestBuilder(CertManagementService::Sptr service,
                                                       data_manager::ClientId client_id)
    : m_service{std::move(service)}, m_client_id{client_id}
{
}

score::crypto::Expected<provider::cert_management::PathValidationRequest, common::DaemonErrorCode>
VerificationRequestBuilder::Build(const Inputs& inputs, std::optional<TrustStoreHandle> trust_store) const
{
    if (!inputs.leaf.has_value() || !inputs.leaf->object)
    {
        score::mw::log::LogError() << kLogPrefix << "The leaf certificate is not set";
        return score::crypto::make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }
    const CertObject& leaf = *inputs.leaf->object;

    // The store handler is resolved once, so the anchors and the CRLs are read from the same store.
    ITrustStoreHandler::Sptr store;
    if (trust_store.has_value())
    {
        store = m_service->GetTrustStoreManager()->GetStore(*trust_store);
        if (!store)
        {
            score::mw::log::LogError() << kLogPrefix << "The bound trust store is not available";
            return score::crypto::make_unexpected(common::DaemonErrorCode::kInternalError);
        }
    }

    // Anchors: the explicit trusted certificates, then the enabled members of the bound store.
    std::vector<CertObject::Sptr> anchors;
    for (const auto& trusted : inputs.trusted)
    {
        AppendUnique(anchors, trusted.object);
    }
    if (store)
    {
        auto members = store->GetAnchors();
        if (!members.has_value())
        {
            return score::crypto::make_unexpected(members.error());
        }
        for (const auto& anchor : members.value())
        {
            AppendUnique(anchors, anchor);
        }
    }
    if (anchors.empty())
    {
        score::mw::log::LogError() << kLogPrefix << "No trust anchor is available for the verification";
        return score::crypto::make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }

    // Untrusted inputs: the presented chain, then the untrusted certificates. The leaf and the anchors are not
    // repeated here.
    std::vector<CertObject::Sptr> untrusted_certs;
    const auto add_untrusted = [&leaf, &anchors, &untrusted_certs](const std::vector<Certificate>& source) {
        for (const auto& entry : source)
        {
            if (!entry.object || SameCertificate(leaf, *entry.object) || Contains(anchors, *entry.object))
            {
                continue;
            }
            AppendUnique(untrusted_certs, entry.object);
        }
    };
    add_untrusted(inputs.chain);
    add_untrusted(inputs.untrusted);

    provider::cert_management::PathValidationRequest request;
    request.leaf = inputs.leaf->object;
    request.untrusted = std::move(untrusted_certs);
    request.trust_anchors = std::move(anchors);
    // Standalone anchors are ephemeral and end the chain at the anchor that was provided, which is what the
    // partial-chain rule expresses. The client's policy applies to trust-store verification only.
    request.chain_termination = trust_store.has_value() ? inputs.chain_termination
                                                        : score::crypto::ChainTerminationPolicy::kTrustStoreTerminated;
    request.revocation_check = inputs.revocation_check;
    request.revocation_coverage = inputs.revocation_coverage;
    request.verification_time_epoch_s = inputs.verification_time_epoch_s;

    if (inputs.revocation_check != score::crypto::RevocationCheckPolicy::kNone)
    {
        std::vector<data_manager::DataNodeId> nodes;
        nodes.push_back(inputs.leaf->node_id);
        for (const auto& entry : inputs.chain)
        {
            nodes.push_back(entry.node_id);
        }
        for (const auto& entry : inputs.untrusted)
        {
            nodes.push_back(entry.node_id);
        }
        for (const auto& entry : inputs.trusted)
        {
            nodes.push_back(entry.node_id);
        }
        for (const auto node_id : nodes)
        {
            // A null snapshot means the node has no CRL; an error means the node could not be read.
            auto crl = m_service->ResolveCrlData(m_client_id, node_id);
            if (!crl.has_value())
            {
                return score::crypto::make_unexpected(crl.error());
            }
            AppendUsableCrl(request.crls, crl.value());
        }
        if (store)
        {
            auto store_crls = store->GetCrls();
            if (!store_crls.has_value())
            {
                return score::crypto::make_unexpected(store_crls.error());
            }
            for (const auto& crl : store_crls.value())
            {
                AppendUsableCrl(request.crls, crl);
            }
        }
    }

    return request;
}

}  // namespace score::crypto::daemon::cert_management

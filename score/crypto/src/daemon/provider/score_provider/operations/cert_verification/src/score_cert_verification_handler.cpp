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

#include "score/crypto/src/daemon/provider/score_provider/operations/cert_verification/score_cert_verification_handler.hpp"
#include "score/crypto/src/daemon/cert_management/core/cert_entry.hpp"
#include "score/crypto/src/daemon/cert_management/slot/slot_registry.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/cert_verification/cert_verification_executor.hpp"
#include "score/mw/log/logging.h"

#include <algorithm>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>

namespace score::crypto::daemon::provider::score_provider::operations::cert_verification
{

namespace
{
constexpr std::string_view LOG_PREFIX = "[SCORE_CERT_VERIFY_HANDLER] ";
}

ScoreCertVerificationHandler::ScoreCertVerificationHandler(
    std::unique_ptr<CertVerificationExecutor> executor,
    std::shared_ptr<::score::crypto::daemon::cert_management::CertManagementService> service)
    : m_executor{std::move(executor)}, m_service{std::move(service)}
{
}

ScoreCertVerificationHandler::~ScoreCertVerificationHandler()
{
    if (m_trust_store_handle.has_value() && m_service)
        m_service->GetTrustStoreManager()->ReleaseRef(*m_trust_store_handle, m_ctx.client_id);
}

Expected<std::monostate, common::DaemonErrorCode> ScoreCertVerificationHandler::InitializeContext(
    const handler::InitializationParams& init_params)
{
    m_ctx.client_id = init_params.client_id;
    m_ctx.context_node_id = init_params.context_node_id;
    if (init_params.provider_id != common::kInvalidProviderId)
        m_ctx.provider_id = init_params.provider_id;
    return std::monostate{};
}

Expected<common::ResponseParameters, common::DaemonErrorCode> ScoreCertVerificationHandler::Execute(
    const common::OperationIdentifier& operationId,
    common::RequestParameters& request)
{
    return m_executor->Execute(*this, operationId, request);
}

Expected<std::monostate, common::DaemonErrorCode> ScoreCertVerificationHandler::Reset()
{
    if (m_trust_store_handle.has_value() && m_service)
        m_service->GetTrustStoreManager()->ReleaseRef(*m_trust_store_handle, m_ctx.client_id);
    m_trust_store_handle.reset();

    m_leaf_cert_entry.reset();
    m_chain_cert_entries.clear();
    m_trust_store_node_id.reset();
    m_trusted_cert_entries.clear();
    m_chain_termination_policy = 0U;
    m_additional_cert_entries.clear();
    m_verification_time_epoch_s.reset();
    m_revocation_policy = 0U;
    m_evidence_mode = score::crypto::VerificationEvidenceMode::kNone;
    m_selected_crl_metadata.clear();
    m_verified_chain.clear();
    return std::monostate{};
}

// ---------------------------------------------------------------------------
// Typed setters — state accumulation
// ---------------------------------------------------------------------------

Expected<std::monostate, common::DaemonErrorCode> ScoreCertVerificationHandler::SetLeaf(uint64_t node_id)
{
    auto entry_res = ResolveCertEntry(node_id);
    if (!entry_res.has_value())
        return make_unexpected(entry_res.error());

    m_leaf_cert_entry = std::move(entry_res.value());
    m_chain_cert_entries.clear();
    return std::monostate{};
}

Expected<std::monostate, common::DaemonErrorCode> ScoreCertVerificationHandler::SetChain(
    const std::vector<uint64_t>& node_ids)
{
    if (node_ids.empty())
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);

    std::vector<CertEntrySptr> entries;
    entries.reserve(node_ids.size());
    for (const auto node_id : node_ids)
    {
        auto entry_res = ResolveCertEntry(node_id);
        if (!entry_res.has_value())
            return make_unexpected(entry_res.error());
        entries.push_back(std::move(entry_res.value()));
    }

    // The public API accepts a complete chain in leaf-first order.
    m_leaf_cert_entry = std::move(entries.front());
    m_chain_cert_entries.assign(entries.begin() + 1U, entries.end());
    return std::monostate{};
}

Expected<std::monostate, common::DaemonErrorCode> ScoreCertVerificationHandler::SetTrustStore(uint64_t node_id)
{
    if (!m_service)
        return make_unexpected(common::DaemonErrorCode::kInternalError);

    auto handle_res = m_service->ResolveTrustStoreForOperation(m_ctx.client_id, node_id);
    if (!handle_res.has_value())
        return make_unexpected(handle_res.error());

    // Release previous trust store before switching
    if (m_trust_store_handle.has_value())
        m_service->GetTrustStoreManager()->ReleaseRef(*m_trust_store_handle, m_ctx.client_id);

    m_service->GetTrustStoreManager()->AddRef(handle_res.value(), m_ctx.client_id);
    m_trust_store_handle = handle_res.value();

    m_trust_store_node_id = node_id;
    return std::monostate{};
}

Expected<std::monostate, common::DaemonErrorCode> ScoreCertVerificationHandler::SetTrusted(
    const std::vector<uint64_t>& node_ids)
{
    std::vector<CertEntrySptr> entries;
    entries.reserve(node_ids.size());
    for (const auto node_id : node_ids)
    {
        auto entry_res = ResolveCertEntry(node_id);
        if (!entry_res.has_value())
            return make_unexpected(entry_res.error());
        entries.push_back(std::move(entry_res.value()));
    }

    m_trusted_cert_entries = std::move(entries);
    return std::monostate{};
}

Expected<std::monostate, common::DaemonErrorCode> ScoreCertVerificationHandler::SetPolicy(uint8_t policy)
{
    m_chain_termination_policy = policy;
    return std::monostate{};
}

Expected<std::monostate, common::DaemonErrorCode> ScoreCertVerificationHandler::SetAdditional(
    const std::vector<uint64_t>& node_ids)
{
    std::vector<CertEntrySptr> entries;
    entries.reserve(node_ids.size());
    for (const auto node_id : node_ids)
    {
        auto entry_res = ResolveCertEntry(node_id);
        if (!entry_res.has_value())
            return make_unexpected(entry_res.error());
        entries.push_back(std::move(entry_res.value()));
    }

    m_additional_cert_entries = std::move(entries);
    return std::monostate{};
}

void ScoreCertVerificationHandler::SetVerificationTime(int64_t epoch_s) noexcept
{
    m_verification_time_epoch_s = epoch_s;
}

void ScoreCertVerificationHandler::SetRevocationPolicy(uint8_t policy) noexcept
{
    m_revocation_policy = policy;
}

void ScoreCertVerificationHandler::SetEvidenceMode(uint8_t mode) noexcept
{
    m_evidence_mode = static_cast<score::crypto::VerificationEvidenceMode>(mode);
}

uint32_t ScoreCertVerificationHandler::GetVerifiedChainCertificateCount() const noexcept
{
    return static_cast<uint32_t>(m_verified_chain.size());
}

// ---------------------------------------------------------------------------
// Verify trigger — resolves node IDs, assembles input, calls DoVerify
// ---------------------------------------------------------------------------

Expected<uint8_t, common::DaemonErrorCode> ScoreCertVerificationHandler::Verify()
{
    if (!m_leaf_cert_entry)
    {
        score::mw::log::LogError() << LOG_PREFIX << "Verify: leaf cert not set";
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }

    VerificationInput input;
    input.chain_termination_policy = m_chain_termination_policy;
    input.trust_store_node_id = m_trust_store_node_id;
    input.verification_time_epoch_s = m_verification_time_epoch_s;
    input.revocation_policy = m_revocation_policy;
    input.evidence_mode = m_evidence_mode;

    // Reset cached chain state from any prior Verify() call.
    m_verified_chain.clear();
    m_selected_crl_metadata.clear();

    // Use entries retained when the setter resolved the caller's resource ID.
    input.leaf = m_leaf_cert_entry->GetCertObject();

    // Use retained chain entries.
    for (const auto& entry : m_chain_cert_entries)
    {
        auto cert = entry->GetCertObject();
        input.chain.push_back(std::move(cert));
    }

    // Resolve additional untrusted certs once in SetAdditional() and retain them.
    for (const auto& entry : m_additional_cert_entries)
    {
        auto cert = entry->GetCertObject();
        input.additional.push_back(std::move(cert));
    }

    // Resolve explicit trusted certs once in SetTrusted() and retain them.
    for (const auto& entry : m_trusted_cert_entries)
    {
        auto cert = entry->GetCertObject();
        input.trusted.push_back(std::move(cert));
    }

    auto append_crl = [this, &input](const CertEntrySptr& entry) -> Expected<std::monostate, common::DaemonErrorCode> {
        if (!entry)
            return std::monostate{};
        if (auto session = entry->GetSessionCrl(); session.has_value())
        {
            input.crls.push_back({std::move(*session), entry->GetSessionCrlFormat()});
            return std::monostate{};
        }
        const auto slot = entry->GetSlotHandle();
        if (!slot.IsValid() || !m_service || !m_service->GetSlotManager())
            return std::monostate{};
        auto& manager = *m_service->GetSlotManager();
        const auto has_crl = manager.HasCrl(slot);
        if (!has_crl)
            return make_unexpected(has_crl.error());
        if (!has_crl.value())
            return std::monostate{};
        auto crl = manager.LoadCrl(slot, m_ctx.client_id);
        if (crl.has_value())
            input.crls.push_back({std::move(*crl), manager.GetCrlFormat(slot)});
        else
            return make_unexpected(crl.error());
        return std::monostate{};
    };
    if (const auto result = append_crl(m_leaf_cert_entry); !result)
        return make_unexpected(result.error());
    for (const auto& entry : m_chain_cert_entries)
    {
        if (const auto result = append_crl(entry); !result)
            return make_unexpected(result.error());
    }
    for (const auto& entry : m_additional_cert_entries)
    {
        if (const auto result = append_crl(entry); !result)
            return make_unexpected(result.error());
    }
    for (const auto& entry : m_trusted_cert_entries)
    {
        if (const auto result = append_crl(entry); !result)
            return make_unexpected(result.error());
    }
    for (const auto& entry : m_trusted_cert_entries)
        append_crl(entry);

    // Trust-store mode: add pre-resolved anchors to any explicit anchors. The
    // effective trust set is the union of both sources, deduplicated by fingerprint.
    if (m_trust_store_node_id.has_value())
    {
        auto handle_res = m_service->ResolveTrustStoreForOperation(m_ctx.client_id, m_trust_store_node_id.value());
        if (!handle_res.has_value())
            return make_unexpected(handle_res.error());
        auto ts = m_service->GetTrustStoreManager()->GetStore(handle_res.value());
        if (!ts)
        {
            score::mw::log::LogError() << LOG_PREFIX << "Verify: trust store not found";
            return make_unexpected(common::DaemonErrorCode::kInternalError);
        }
        auto anchors_res = ts->GetAnchors();
        if (!anchors_res.has_value())
            return make_unexpected(anchors_res.error());

        for (auto& anchor : anchors_res.value())
        {
            if (!anchor)
                continue;
            const auto fingerprint = anchor->GetFingerprint();
            const auto already_present =
                std::any_of(input.trusted.begin(), input.trusted.end(), [&fingerprint](const auto& existing) {
                    if (!existing)
                        return false;
                    const auto existing_fingerprint = existing->GetFingerprint();
                    return existing_fingerprint.size() == fingerprint.size() &&
                           std::equal(existing_fingerprint.begin(), existing_fingerprint.end(), fingerprint.begin());
                });
            if (!already_present)
                input.trusted.push_back(std::move(anchor));
        }
        if (input.trusted.empty())
        {
            score::mw::log::LogError() << LOG_PREFIX << "Verify: trust store has no usable anchors";
            return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
        }

        // Pass the handler to DoVerify so it can call GetCrls() lazily when
        // kCrlOnly is requested. CRLs are cached alongside anchors in the handler.
        if (input.revocation_policy != 0U)
            input.trust_store_handler = ts;
        for (const auto& crl : ts->GetCrls())
            input.crls.push_back(crl);
    }

    auto verify_res = DoVerify(input);
    if (!verify_res.has_value())
        return make_unexpected(verify_res.error());

    m_verified_chain = std::move(verify_res.value().chain);
    m_selected_crl_metadata = std::move(verify_res.value().selected_crl_metadata);
    return verify_res.value().result_code;
}

Expected<common::OwnedBuffer, common::DaemonErrorCode> ScoreCertVerificationHandler::EncodeCertificate(
    const CertSptr& cert,
    score::crypto::FormatType format) const
{
    if (!cert)
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    if (format != score::crypto::FormatType::kDer && format != score::crypto::FormatType::kPem)
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    if (cert->GetFormat() != format)
        return make_unexpected(common::DaemonErrorCode::kUnsupportedOperation);

    const auto raw = cert->GetRawBytes();
    return common::OwnedBuffer(raw.begin(), raw.end());
}

Expected<std::size_t, common::DaemonErrorCode> ScoreCertVerificationHandler::GetVerifiedChainExportSize(
    score::crypto::FormatType format) const
{
    auto export_res = ExportVerifiedChain(format);
    if (!export_res.has_value())
        return make_unexpected(export_res.error());
    return export_res.value().size();
}

Expected<common::OwnedBuffer, common::DaemonErrorCode> ScoreCertVerificationHandler::ExportVerifiedChain(
    score::crypto::FormatType format) const
{
    if (m_verified_chain.empty())
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);

    common::OwnedBuffer output;
    for (const auto& cert : m_verified_chain)
    {
        auto cert_res = EncodeCertificate(cert, format);
        if (!cert_res.has_value())
            return make_unexpected(cert_res.error());
        auto& encoded = cert_res.value();
        output.insert(output.end(), encoded.begin(), encoded.end());
    }
    return output;
}

Expected<common::OwnedBuffer, common::DaemonErrorCode> ScoreCertVerificationHandler::GetSelectedCrlMetadata() const
{
    if (m_evidence_mode != score::crypto::VerificationEvidenceMode::kChainAndCrl)
        return make_unexpected(common::DaemonErrorCode::kUnsupportedOperation);
    return m_selected_crl_metadata;
}

Expected<std::size_t, common::DaemonErrorCode> ScoreCertVerificationHandler::GetVerifiedCertificateExportSize(
    std::size_t index,
    score::crypto::FormatType format) const
{
    auto export_res = ExportVerifiedCertificate(index, format);
    if (!export_res.has_value())
        return make_unexpected(export_res.error());
    return export_res.value().size();
}

Expected<common::OwnedBuffer, common::DaemonErrorCode> ScoreCertVerificationHandler::ExportVerifiedCertificate(
    std::size_t index,
    score::crypto::FormatType format) const
{
    if (index >= m_verified_chain.size())
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    return EncodeCertificate(m_verified_chain[index], format);
}

// ---------------------------------------------------------------------------
// Private helper
// ---------------------------------------------------------------------------

Expected<ScoreCertVerificationHandler::CertEntrySptr, common::DaemonErrorCode>
ScoreCertVerificationHandler::ResolveCertEntry(uint64_t node_id) const
{
    if (!m_service)
        return make_unexpected(common::DaemonErrorCode::kInternalError);
    return m_service->ResolveCertEntryForOperation(m_ctx.client_id, node_id);
}

// ---------------------------------------------------------------------------
// Default DoVerify — overridden by concrete providers
// ---------------------------------------------------------------------------

Expected<ScoreCertVerificationHandler::VerifyOutcome, common::DaemonErrorCode> ScoreCertVerificationHandler::DoVerify(
    const VerificationInput& /*input*/)
{
    return make_unexpected(common::DaemonErrorCode::kUnsupportedOperation);
}

}  // namespace score::crypto::daemon::provider::score_provider::operations::cert_verification

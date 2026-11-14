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

#include "score/crypto/src/daemon/cert_management/context/verification/session.hpp"

#include "score/mw/log/logging.h"

#include <string_view>
#include <utility>

namespace score::crypto::daemon::cert_management
{

namespace
{

constexpr std::string_view kLogPrefix{"[CERT_VERIFY_SESSION] "};

}  // namespace

CertVerificationSession::CertVerificationSession(CertExecutionContext ctx, Services services)
    : m_ctx{ctx},
      m_services{std::move(services)},
      m_request_builder{m_services.service, m_ctx.client_id},
      m_binding{m_services.service->GetTrustStoreManager(), m_ctx.client_id},
      m_encoder{m_services.parser}
{
}

score::crypto::Expected<std::monostate, common::DaemonErrorCode> CertVerificationSession::SetLeaf(
    data_manager::DataNodeId node_id)
{
    auto certificate = ResolveCertificate(node_id);
    if (!certificate.has_value())
    {
        return score::crypto::make_unexpected(certificate.error());
    }
    m_inputs.leaf = std::move(certificate.value());
    m_inputs.chain.clear();
    return std::monostate{};
}

score::crypto::Expected<std::monostate, common::DaemonErrorCode> CertVerificationSession::SetChain(
    const std::vector<data_manager::DataNodeId>& node_ids)
{
    if (node_ids.empty())
    {
        score::mw::log::LogError() << kLogPrefix << "SetChain received an empty chain";
        return score::crypto::make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }
    auto resolved = ResolveCertificates(node_ids);
    if (!resolved.has_value())
    {
        return score::crypto::make_unexpected(resolved.error());
    }
    // The first node is the leaf; the remaining nodes form the presented chain.
    m_inputs.leaf = resolved.value().front();
    m_inputs.chain.assign(resolved.value().begin() + 1, resolved.value().end());
    return std::monostate{};
}

score::crypto::Expected<std::monostate, common::DaemonErrorCode> CertVerificationSession::SetTrustStore(
    data_manager::DataNodeId node_id)
{
    auto handle = m_services.service->ResolveTrustStoreHandle(m_ctx.client_id, node_id);
    if (!handle.has_value())
    {
        return score::crypto::make_unexpected(handle.error());
    }
    return m_binding.Bind(handle.value());
}

score::crypto::Expected<std::monostate, common::DaemonErrorCode> CertVerificationSession::SetTrusted(
    const std::vector<data_manager::DataNodeId>& node_ids)
{
    auto resolved = ResolveCertificates(node_ids);
    if (!resolved.has_value())
    {
        return score::crypto::make_unexpected(resolved.error());
    }
    m_inputs.trusted = std::move(resolved.value());
    return std::monostate{};
}

score::crypto::Expected<std::monostate, common::DaemonErrorCode> CertVerificationSession::SetUntrusted(
    const std::vector<data_manager::DataNodeId>& node_ids)
{
    auto resolved = ResolveCertificates(node_ids);
    if (!resolved.has_value())
    {
        return score::crypto::make_unexpected(resolved.error());
    }
    m_inputs.untrusted = std::move(resolved.value());
    return std::monostate{};
}

void CertVerificationSession::SetChainTerminationPolicy(score::crypto::ChainTerminationPolicy policy) noexcept
{
    m_inputs.chain_termination = policy;
}

void CertVerificationSession::SetVerificationTime(std::int64_t epoch_s) noexcept
{
    m_inputs.verification_time_epoch_s = epoch_s;
}

void CertVerificationSession::SetRevocationCheckPolicy(score::crypto::RevocationCheckPolicy policy) noexcept
{
    m_inputs.revocation_check = policy;
}

void CertVerificationSession::SetRevocationCoveragePolicy(score::crypto::RevocationCoveragePolicy policy) noexcept
{
    m_inputs.revocation_coverage = policy;
}

void CertVerificationSession::SetEvidenceMode(score::crypto::VerificationEvidenceMode mode) noexcept
{
    m_evidence_mode = mode;
}

score::crypto::Expected<score::crypto::CertVerifyResult, common::DaemonErrorCode> CertVerificationSession::Verify()
{
    // A new verification replaces the previous result, including when it fails.
    m_verified_chain.clear();
    m_selected_crl_metadata.clear();

    auto request = m_request_builder.Build(m_inputs, m_binding.Handle());
    if (!request.has_value())
    {
        return score::crypto::make_unexpected(request.error());
    }

    // An error from the validator is an infrastructure failure. A verdict, including a failed one, is a result.
    auto outcome = m_services.validator->Validate(request.value());
    if (!outcome.has_value())
    {
        return score::crypto::make_unexpected(outcome.error());
    }

    auto& result = outcome.value();
    m_selected_crl_metadata = std::move(result.selected_crl_metadata);
    if (result.result == score::crypto::CertVerifyResult::kValid)
    {
        m_verified_chain = std::move(result.chain);
    }
    return result.result;
}

std::uint32_t CertVerificationSession::GetVerifiedChainCertificateCount() const noexcept
{
    return static_cast<std::uint32_t>(m_verified_chain.size());
}

score::crypto::Expected<std::vector<std::uint8_t>, common::DaemonErrorCode>
CertVerificationSession::ExportVerifiedChain(score::crypto::FormatType format) const
{
    if (m_verified_chain.empty())
    {
        return score::crypto::make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }
    return m_encoder.EncodeChain(m_verified_chain, format);
}

score::crypto::Expected<std::vector<std::uint8_t>, common::DaemonErrorCode>
CertVerificationSession::ExportVerifiedCertificate(std::size_t index, score::crypto::FormatType format) const
{
    if (index >= m_verified_chain.size())
    {
        return score::crypto::make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }
    return m_encoder.EncodeCertificate(*m_verified_chain[index], format);
}

score::crypto::Expected<std::vector<std::uint8_t>, common::DaemonErrorCode>
CertVerificationSession::GetSelectedCrlMetadata() const
{
    if (m_evidence_mode != score::crypto::VerificationEvidenceMode::kChainAndCrl)
    {
        return score::crypto::make_unexpected(common::DaemonErrorCode::kUnsupportedOperation);
    }
    return VerifiedResultEncoder::PackCrlMetadata(m_selected_crl_metadata);
}

void CertVerificationSession::Reset()
{
    m_binding.Release();
    m_inputs = VerificationRequestBuilder::Inputs{};
    m_evidence_mode = score::crypto::VerificationEvidenceMode::kNone;
    m_verified_chain.clear();
    m_selected_crl_metadata.clear();
}

score::crypto::Expected<VerificationRequestBuilder::Certificate, common::DaemonErrorCode>
CertVerificationSession::ResolveCertificate(data_manager::DataNodeId node_id) const
{
    auto object = m_services.service->ResolveCertObject(m_ctx.client_id, node_id);
    if (!object.has_value())
    {
        return score::crypto::make_unexpected(object.error());
    }
    if (!object.value())
    {
        return score::crypto::make_unexpected(common::DaemonErrorCode::kInternalError);
    }
    return VerificationRequestBuilder::Certificate{node_id, std::move(object.value())};
}

score::crypto::Expected<std::vector<VerificationRequestBuilder::Certificate>, common::DaemonErrorCode>
CertVerificationSession::ResolveCertificates(const std::vector<data_manager::DataNodeId>& node_ids) const
{
    std::vector<VerificationRequestBuilder::Certificate> resolved;
    resolved.reserve(node_ids.size());
    for (const auto node_id : node_ids)
    {
        auto certificate = ResolveCertificate(node_id);
        if (!certificate.has_value())
        {
            return score::crypto::make_unexpected(certificate.error());
        }
        resolved.push_back(std::move(certificate.value()));
    }
    return resolved;
}

}  // namespace score::crypto::daemon::cert_management

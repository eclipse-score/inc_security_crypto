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

#include "score/crypto/src/daemon/provider/score_provider/operations/cert_verification/cert_verification_executor.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/cert_verification_operations.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/cert_verification/score_cert_verification_handler.hpp"
#include "score/mw/log/logging.h"

#include <cstring>
#include <string_view>

namespace score::crypto::daemon::provider::score_provider::operations::cert_verification
{

namespace
{
constexpr std::string_view LOG_PREFIX = "[CERT_VERIFY_EXEC] ";
namespace cv_ops = provider::cert_verification;

Expected<std::uint64_t, common::DaemonErrorCode> ExtractU64(const common::RequestParameters& p, std::size_t idx)
{
    if (p.size() <= idx)
        return make_unexpected(common::DaemonErrorCode::kInsufficientParameters);
    const auto* v = std::get_if<std::uint64_t>(&p[idx]);
    if (!v)
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    return *v;
}

Expected<std::uint8_t, common::DaemonErrorCode> ExtractU8(const common::RequestParameters& p, std::size_t idx)
{
    if (p.size() <= idx)
        return make_unexpected(common::DaemonErrorCode::kInsufficientParameters);
    const auto* v = std::get_if<std::uint8_t>(&p[idx]);
    if (!v)
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    return *v;
}

common::ResponseParameters OkResponse()
{
    common::ResponseParameters out;
    out.push_back(static_cast<std::uint64_t>(0U));
    return out;
}

}  // namespace

Expected<common::ResponseParameters, common::DaemonErrorCode> CertVerificationExecutor::Execute(
    ScoreCertVerificationHandler& handler,
    const common::OperationIdentifier& operationId,
    common::RequestParameters& request)
{
    const auto action = operationId.operationAction;

    if (action == cv_ops::CERT_VERIFY_SET_LEAF)
        return ExecuteSetLeaf(handler, request);
    if (action == cv_ops::CERT_VERIFY_SET_CHAIN)
        return ExecuteSetChain(handler, request);
    if (action == cv_ops::CERT_VERIFY_SET_TRUST_STORE)
        return ExecuteSetTrustStore(handler, request);
    if (action == cv_ops::CERT_VERIFY_SET_TRUSTED)
        return ExecuteSetTrusted(handler, request);
    if (action == cv_ops::CERT_VERIFY_SET_POLICY)
        return ExecuteSetPolicy(handler, request);
    if (action == cv_ops::CERT_VERIFY_SET_ADDITIONAL)
        return ExecuteSetAdditional(handler, request);
    if (action == cv_ops::CERT_VERIFY_SET_VERIFICATION_TIME)
        return ExecuteSetVerificationTime(handler, request);
    if (action == cv_ops::CERT_VERIFY_SET_REVOCATION_POLICY)
        return ExecuteSetRevocationPolicy(handler, request);
    if (action == cv_ops::CERT_VERIFY_SET_EVIDENCE_MODE)
        return ExecuteSetEvidenceMode(handler, request);
    if (action == cv_ops::CERT_VERIFY)
        return ExecuteVerify(handler);
    if (action == cv_ops::CERT_GET_VERIFIED_CHAIN_EXPORT_SIZE)
        return ExecuteGetVerifiedChainExportSize(handler, request);
    if (action == cv_ops::CERT_EXPORT_VERIFIED_CHAIN)
        return ExecuteExportVerifiedChain(handler, request);
    if (action == cv_ops::CERT_GET_VERIFIED_CERT_EXPORT_SIZE)
        return ExecuteGetVerifiedCertificateExportSize(handler, request);
    if (action == cv_ops::CERT_EXPORT_VERIFIED_CERT)
        return ExecuteExportVerifiedCertificate(handler, request);
    if (action == cv_ops::CERT_GET_SELECTED_CRL_METADATA)
        return ExecuteGetSelectedCrlMetadata(handler);

    score::mw::log::LogError() << LOG_PREFIX << "Unknown action 0x" << score::mw::log::LogHex16{action};
    return make_unexpected(common::DaemonErrorCode::kUnsupportedOperation);
}

Expected<common::ResponseParameters, common::DaemonErrorCode> CertVerificationExecutor::ExecuteSetLeaf(
    ScoreCertVerificationHandler& handler,
    common::RequestParameters& request)
{
    auto id = ExtractU64(request, 0U);
    if (!id.has_value())
        return make_unexpected(id.error());
    auto res = handler.SetLeaf(id.value());
    if (!res.has_value())
        return make_unexpected(res.error());
    return OkResponse();
}

Expected<common::ResponseParameters, common::DaemonErrorCode> CertVerificationExecutor::ExecuteSetChain(
    ScoreCertVerificationHandler& handler,
    common::RequestParameters& request)
{
    std::vector<std::uint64_t> ids;
    ids.reserve(request.size());
    for (std::size_t i = 0U; i < request.size(); ++i)
    {
        auto id = ExtractU64(request, i);
        if (!id.has_value())
            return make_unexpected(id.error());
        ids.push_back(id.value());
    }
    auto res = handler.SetChain(ids);
    if (!res.has_value())
        return make_unexpected(res.error());
    return OkResponse();
}

Expected<common::ResponseParameters, common::DaemonErrorCode> CertVerificationExecutor::ExecuteSetTrustStore(
    ScoreCertVerificationHandler& handler,
    common::RequestParameters& request)
{
    auto id = ExtractU64(request, 0U);
    if (!id.has_value())
        return make_unexpected(id.error());
    auto res = handler.SetTrustStore(id.value());
    if (!res.has_value())
        return make_unexpected(res.error());
    return OkResponse();
}

Expected<common::ResponseParameters, common::DaemonErrorCode> CertVerificationExecutor::ExecuteSetTrusted(
    ScoreCertVerificationHandler& handler,
    common::RequestParameters& request)
{
    std::vector<std::uint64_t> ids;
    ids.reserve(request.size());
    for (std::size_t i = 0U; i < request.size(); ++i)
    {
        auto id = ExtractU64(request, i);
        if (!id.has_value())
            return make_unexpected(id.error());
        ids.push_back(id.value());
    }

    auto res = handler.SetTrusted(ids);
    if (!res.has_value())
        return make_unexpected(res.error());
    return OkResponse();
}

Expected<common::ResponseParameters, common::DaemonErrorCode> CertVerificationExecutor::ExecuteSetPolicy(
    ScoreCertVerificationHandler& handler,
    common::RequestParameters& request)
{
    auto policy = ExtractU8(request, 0U);
    if (!policy.has_value())
        return make_unexpected(policy.error());
    auto res = handler.SetPolicy(policy.value());
    if (!res.has_value())
        return make_unexpected(res.error());
    return OkResponse();
}

Expected<common::ResponseParameters, common::DaemonErrorCode> CertVerificationExecutor::ExecuteSetAdditional(
    ScoreCertVerificationHandler& handler,
    common::RequestParameters& request)
{
    std::vector<std::uint64_t> ids;
    ids.reserve(request.size());
    for (std::size_t i = 0U; i < request.size(); ++i)
    {
        auto id = ExtractU64(request, i);
        if (!id.has_value())
            return make_unexpected(id.error());
        ids.push_back(id.value());
    }
    auto res = handler.SetAdditional(ids);
    if (!res.has_value())
        return make_unexpected(res.error());
    return OkResponse();
}

Expected<common::ResponseParameters, common::DaemonErrorCode> CertVerificationExecutor::ExecuteSetVerificationTime(
    ScoreCertVerificationHandler& handler,
    common::RequestParameters& request)
{
    if (request.size() < 1U)
        return make_unexpected(common::DaemonErrorCode::kInsufficientParameters);
    const auto* v = std::get_if<std::uint64_t>(&request[0U]);
    if (!v)
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    handler.SetVerificationTime(static_cast<int64_t>(*v));
    return OkResponse();
}

Expected<common::ResponseParameters, common::DaemonErrorCode> CertVerificationExecutor::ExecuteSetRevocationPolicy(
    ScoreCertVerificationHandler& handler,
    common::RequestParameters& request)
{
    auto policy = ExtractU8(request, 0U);
    if (!policy.has_value())
        return make_unexpected(policy.error());
    handler.SetRevocationPolicy(policy.value());
    return OkResponse();
}

Expected<common::ResponseParameters, common::DaemonErrorCode> CertVerificationExecutor::ExecuteSetEvidenceMode(
    ScoreCertVerificationHandler& handler,
    common::RequestParameters& request)
{
    auto mode = ExtractU8(request, 0U);
    if (!mode.has_value())
        return make_unexpected(mode.error());
    if (mode.value() > static_cast<std::uint8_t>(score::crypto::VerificationEvidenceMode::kChainAndCrl))
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    handler.SetEvidenceMode(mode.value());
    return OkResponse();
}

Expected<common::ResponseParameters, common::DaemonErrorCode> CertVerificationExecutor::ExecuteVerify(
    ScoreCertVerificationHandler& handler)
{
    auto res = handler.Verify();
    if (!res.has_value())
        return make_unexpected(res.error());

    common::ResponseParameters out;
    out.push_back(static_cast<std::uint8_t>(res.value()));  // param[0]: CertVerifyResult
    out.push_back(
        static_cast<std::uint32_t>(handler.GetVerifiedChainCertificateCount()));  // param[1]: certificate count
    return out;
}

Expected<common::ResponseParameters, common::DaemonErrorCode>
CertVerificationExecutor::ExecuteGetVerifiedChainExportSize(ScoreCertVerificationHandler& handler,
                                                            common::RequestParameters& request)
{
    auto format = ExtractU8(request, 0U);
    if (!format.has_value())
        return make_unexpected(format.error());
    auto size = handler.GetVerifiedChainExportSize(static_cast<score::crypto::FormatType>(format.value()));
    if (!size.has_value())
        return make_unexpected(size.error());
    common::ResponseParameters out;
    out.push_back(static_cast<std::uint64_t>(size.value()));
    return out;
}

Expected<common::ResponseParameters, common::DaemonErrorCode> CertVerificationExecutor::ExecuteExportVerifiedChain(
    ScoreCertVerificationHandler& handler,
    common::RequestParameters& request)
{
    auto format = ExtractU8(request, 0U);
    if (!format.has_value())
        return make_unexpected(format.error());
    auto bytes = handler.ExportVerifiedChain(static_cast<score::crypto::FormatType>(format.value()));
    if (!bytes.has_value())
        return make_unexpected(bytes.error());
    common::ResponseParameters out;
    out.push_back(static_cast<std::uint64_t>(bytes.value().size()));
    out.push_back(std::move(bytes.value()));
    return out;
}

Expected<common::ResponseParameters, common::DaemonErrorCode>
CertVerificationExecutor::ExecuteGetVerifiedCertificateExportSize(ScoreCertVerificationHandler& handler,
                                                                  common::RequestParameters& request)
{
    auto index = ExtractU64(request, 0U);
    auto format = ExtractU8(request, 1U);
    if (!index.has_value())
        return make_unexpected(index.error());
    if (!format.has_value())
        return make_unexpected(format.error());
    auto size = handler.GetVerifiedCertificateExportSize(static_cast<std::size_t>(index.value()),
                                                         static_cast<score::crypto::FormatType>(format.value()));
    if (!size.has_value())
        return make_unexpected(size.error());
    common::ResponseParameters out;
    out.push_back(static_cast<std::uint64_t>(size.value()));
    return out;
}

Expected<common::ResponseParameters, common::DaemonErrorCode>
CertVerificationExecutor::ExecuteExportVerifiedCertificate(ScoreCertVerificationHandler& handler,
                                                           common::RequestParameters& request)
{
    auto index = ExtractU64(request, 0U);
    auto format = ExtractU8(request, 1U);
    if (!index.has_value())
        return make_unexpected(index.error());
    if (!format.has_value())
        return make_unexpected(format.error());
    auto bytes = handler.ExportVerifiedCertificate(static_cast<std::size_t>(index.value()),
                                                   static_cast<score::crypto::FormatType>(format.value()));
    if (!bytes.has_value())
        return make_unexpected(bytes.error());
    common::ResponseParameters out;
    out.push_back(std::move(bytes.value()));
    return out;
}

Expected<common::ResponseParameters, common::DaemonErrorCode> CertVerificationExecutor::ExecuteGetSelectedCrlMetadata(
    ScoreCertVerificationHandler& handler)
{
    auto metadata = handler.GetSelectedCrlMetadata();
    if (!metadata.has_value())
        return make_unexpected(metadata.error());
    common::ResponseParameters out;
    if (metadata.value().size() % score::crypto::CrlMetadataWireLayout::kEntrySize != 0U)
        return make_unexpected(common::DaemonErrorCode::kInternalError);
    out.push_back(
        static_cast<std::uint64_t>(metadata.value().size() / score::crypto::CrlMetadataWireLayout::kEntrySize));
    out.push_back(std::move(metadata.value()));
    return out;
}

}  // namespace score::crypto::daemon::provider::score_provider::operations::cert_verification

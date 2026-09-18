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

#include "score/crypto/src/daemon/provider/executors/trust_store_mgmt_executor.hpp"
#include "score/crypto/src/daemon/provider/cert_management/cert_management_operations.hpp"
#include "score/mw/log/logging.h"

#include <cstdint>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

namespace score::crypto::daemon::provider::crypto_executor
{

namespace
{
constexpr std::string_view LOG_PREFIX = "[TRUST_STORE_MGMT_EXEC] ";
namespace cm_ops = provider::cert_management;
using Error = daemon::common::DaemonErrorCode;

/// Extract uint64 at position index; return error on mismatch or missing.
Expected<std::uint64_t, Error> ExtractU64(const common::RequestParameters& p, std::size_t idx)
{
    if (p.size() <= idx)
        return score::crypto::make_unexpected(Error::kInsufficientParameters);
    const auto* v = std::get_if<std::uint64_t>(&p[idx]);
    if (!v)
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    return *v;
}

/// Extract uint8 at position index.
Expected<std::uint8_t, Error> ExtractU8(const common::RequestParameters& p, std::size_t idx)
{
    if (p.size() <= idx)
        return score::crypto::make_unexpected(Error::kInsufficientParameters);
    const auto* v = std::get_if<std::uint8_t>(&p[idx]);
    if (!v)
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    return *v;
}

/// Extract a const-span byte buffer at position index.
Expected<score::crypto::span<const uint8_t>, Error> ExtractBytes(const common::RequestParameters& p, std::size_t idx)
{
    if (p.size() <= idx)
        return score::crypto::make_unexpected(Error::kInsufficientParameters);
    const auto* v = std::get_if<score::crypto::span<const uint8_t>>(&p[idx]);
    if (!v)
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    return *v;
}

common::ResponseParameters OkResponse()
{
    common::ResponseParameters out;
    out.push_back(static_cast<std::uint64_t>(0U));
    return out;
}

}  // namespace

TrustStoreManagementExecutor::TrustStoreManagementExecutor(
    cert_management::ICertParser::Sptr cert_parser,
    std::shared_ptr<::score::crypto::daemon::cert_management::CertManagementService> service)
    : m_cert_parser{std::move(cert_parser)}, m_service{std::move(service)}
{
}

Expected<common::ResponseParameters, Error> TrustStoreManagementExecutor::Execute(
    const CertMgmtExecutionContext& ctx,
    const common::OperationIdentifier& operationId,
    common::RequestParameters& request)
{
    const auto action = operationId.operationAction;

    if (action == cm_ops::TRUST_STORE_ADD_CERT)
        return HandleTrustStoreAdd(ctx, request);
    if (action == cm_ops::TRUST_STORE_REMOVE_CERT)
        return HandleTrustStoreRemove(ctx, request);
    if (action == cm_ops::TRUST_STORE_REMOVE_CERT_BY_ID)
        return HandleTrustStoreRemoveById(ctx, request);
    if (action == cm_ops::TRUST_STORE_ENABLE_CERT)
        return HandleTrustStoreEnable(ctx, request);
    if (action == cm_ops::TRUST_STORE_DISABLE_CERT)
        return HandleTrustStoreDisable(ctx, request);
    if (action == cm_ops::TRUST_STORE_ACK_UPDATE)
        return HandleTrustStoreAckUpdate(ctx, request);
    if (action == cm_ops::TRUST_STORE_IMPORT_CRL_FOR_MEMBER)
        return HandleTrustStoreImportCrlForMember(ctx, request);
    if (action == cm_ops::TRUST_STORE_DELETE_CRL_FOR_MEMBER)
        return HandleTrustStoreDeleteCrlForMember(ctx, request);

    score::mw::log::LogError() << LOG_PREFIX << "Unknown action 0x" << score::mw::log::LogHex16{action};
    return score::crypto::make_unexpected(Error::kUnsupportedOperation);
}

// ---------------------------------------------------------------------------
// Trust store mutations
// ---------------------------------------------------------------------------

// Parameter layout:
//   request[0] = ts_node_id (uint64)
//   request[1] = cert_node_id (uint64)
//   request[2] = with_crl (uint8, optional)
Expected<common::ResponseParameters, Error> TrustStoreManagementExecutor::HandleTrustStoreAdd(
    const CertMgmtExecutionContext& ctx,
    common::RequestParameters& request)
{
    auto ts_nid_res = ExtractU64(request, 0U);
    if (!ts_nid_res.has_value())
        return score::crypto::make_unexpected(ts_nid_res.error());
    auto cert_nid_res = ExtractU64(request, 1U);
    if (!cert_nid_res.has_value())
        return score::crypto::make_unexpected(cert_nid_res.error());

    auto ts_handle_res = m_service->ResolveTrustStoreForOperation(ctx.client_id, ts_nid_res.value());
    if (!ts_handle_res.has_value())
        return score::crypto::make_unexpected(ts_handle_res.error());

    auto cert_res = m_service->ResolveCertForOperation(ctx.client_id, cert_nid_res.value());
    if (!cert_res.has_value())
        return score::crypto::make_unexpected(cert_res.error());

    score::crypto::daemon::cert_management::ResolvedCrl resolved_crl;
    score::crypto::span<const uint8_t> crl_span{};
    score::crypto::FormatType crl_format = score::crypto::FormatType::kDer;
    std::optional<score::crypto::CrlMetadata> crl_metadata;

    if (request.size() > 2U)
    {
        auto wcrl_res = ExtractU8(request, 2U);
        if (wcrl_res.has_value() && wcrl_res.value() != 0U)
        {
            auto crl_res = m_service->ResolveCrlForOperation(ctx.client_id, cert_nid_res.value());
            if (!crl_res.has_value())
                return score::crypto::make_unexpected(crl_res.error());
            if (crl_res.value().has_value())
            {
                resolved_crl = std::move(*crl_res.value());
                crl_span = score::crypto::span<const uint8_t>(resolved_crl.bytes.data(), resolved_crl.bytes.size());
                crl_format = resolved_crl.format;
                crl_metadata = resolved_crl.metadata;
            }
        }
    }

    auto result = m_service->GetTrustStoreManager()->AddMember(
        ts_handle_res.value(), cert_res.value(), ctx.client_id, crl_span, crl_format, std::move(crl_metadata));
    if (!result.has_value())
        return score::crypto::make_unexpected(result.error());
    return OkResponse();
}

// Parameter layout:
//   request[0] = ts_node_id (uint64)
//   request[1] = fingerprint bytes (span<const uint8_t>)
Expected<common::ResponseParameters, Error> TrustStoreManagementExecutor::HandleTrustStoreRemove(
    const CertMgmtExecutionContext& ctx,
    common::RequestParameters& request)
{
    auto ts_nid_res = ExtractU64(request, 0U);
    if (!ts_nid_res.has_value())
        return score::crypto::make_unexpected(ts_nid_res.error());
    auto fp_res = ExtractBytes(request, 1U);
    if (!fp_res.has_value())
        return score::crypto::make_unexpected(fp_res.error());

    auto ts_handle_res = m_service->ResolveTrustStoreForOperation(ctx.client_id, ts_nid_res.value());
    if (!ts_handle_res.has_value())
        return score::crypto::make_unexpected(ts_handle_res.error());

    const auto& fp_span = fp_res.value();
    std::vector<uint8_t> fp_vec(fp_span.begin(), fp_span.end());
    auto result = m_service->GetTrustStoreManager()->RemoveMember(ts_handle_res.value(), fp_vec, ctx.client_id);
    if (!result.has_value())
        return score::crypto::make_unexpected(result.error());
    return OkResponse();
}

// Parameter layout:
//   request[0] = ts_node_id (uint64)
//   request[1] = cert_node_id (uint64)
// Resolves fingerprint from the in-memory CertObject to call RemoveMember.
Expected<common::ResponseParameters, Error> TrustStoreManagementExecutor::HandleTrustStoreRemoveById(
    const CertMgmtExecutionContext& ctx,
    common::RequestParameters& request)
{
    auto ts_nid_res = ExtractU64(request, 0U);
    if (!ts_nid_res.has_value())
        return score::crypto::make_unexpected(ts_nid_res.error());
    auto cert_nid_res = ExtractU64(request, 1U);
    if (!cert_nid_res.has_value())
        return score::crypto::make_unexpected(cert_nid_res.error());

    auto ts_handle_res = m_service->ResolveTrustStoreForOperation(ctx.client_id, ts_nid_res.value());
    if (!ts_handle_res.has_value())
        return score::crypto::make_unexpected(ts_handle_res.error());
    auto cert_res = m_service->ResolveCertForOperation(ctx.client_id, cert_nid_res.value());
    if (!cert_res.has_value())
        return score::crypto::make_unexpected(cert_res.error());

    const auto fp_span = cert_res.value()->GetFingerprint();
    const std::vector<uint8_t> fp_vec(fp_span.begin(), fp_span.end());
    auto result = m_service->GetTrustStoreManager()->RemoveMember(ts_handle_res.value(), fp_vec, ctx.client_id);
    if (!result.has_value())
        return score::crypto::make_unexpected(result.error());
    return OkResponse();
}

// Parameter layout:
//   request[0] = ts_node_id (uint64)
//   request[1] = slot_node_id (uint64) — from MemberInfo::slot_id.id
Expected<common::ResponseParameters, Error> TrustStoreManagementExecutor::HandleTrustStoreEnable(
    const CertMgmtExecutionContext& ctx,
    common::RequestParameters& request)
{
    auto ts_nid_res = ExtractU64(request, 0U);
    if (!ts_nid_res.has_value())
        return score::crypto::make_unexpected(ts_nid_res.error());
    auto slot_nid_res = ExtractU64(request, 1U);
    if (!slot_nid_res.has_value())
        return score::crypto::make_unexpected(slot_nid_res.error());

    auto ts_handle_res = m_service->ResolveTrustStoreForOperation(ctx.client_id, ts_nid_res.value());
    if (!ts_handle_res.has_value())
        return score::crypto::make_unexpected(ts_handle_res.error());
    auto slot_res = m_service->ResolveSlotForOperation(ctx.client_id, slot_nid_res.value());
    if (!slot_res.has_value())
        return score::crypto::make_unexpected(Error::kInvalidArgument);

    auto result =
        m_service->GetTrustStoreManager()->EnableMember(ts_handle_res.value(), slot_res.value().handle, ctx.client_id);
    if (!result.has_value())
        return score::crypto::make_unexpected(result.error());
    return OkResponse();
}

// Parameter layout:
//   request[0] = ts_node_id (uint64)
//   request[1] = slot_node_id (uint64) — from MemberInfo::slot_id.id
Expected<common::ResponseParameters, Error> TrustStoreManagementExecutor::HandleTrustStoreDisable(
    const CertMgmtExecutionContext& ctx,
    common::RequestParameters& request)
{
    auto ts_nid_res = ExtractU64(request, 0U);
    if (!ts_nid_res.has_value())
        return score::crypto::make_unexpected(ts_nid_res.error());
    auto slot_nid_res = ExtractU64(request, 1U);
    if (!slot_nid_res.has_value())
        return score::crypto::make_unexpected(slot_nid_res.error());

    auto ts_handle_res = m_service->ResolveTrustStoreForOperation(ctx.client_id, ts_nid_res.value());
    if (!ts_handle_res.has_value())
        return score::crypto::make_unexpected(ts_handle_res.error());
    auto slot_res = m_service->ResolveSlotForOperation(ctx.client_id, slot_nid_res.value());
    if (!slot_res.has_value())
        return score::crypto::make_unexpected(Error::kInvalidArgument);

    auto result =
        m_service->GetTrustStoreManager()->DisableMember(ts_handle_res.value(), slot_res.value().handle, ctx.client_id);
    if (!result.has_value())
        return score::crypto::make_unexpected(result.error());
    return OkResponse();
}

Expected<common::ResponseParameters, Error> TrustStoreManagementExecutor::HandleTrustStoreAckUpdate(
    const CertMgmtExecutionContext& ctx,
    common::RequestParameters& request)
{
    auto ts_nid_res = ExtractU64(request, 0U);
    if (!ts_nid_res.has_value())
        return score::crypto::make_unexpected(ts_nid_res.error());
    auto slot_nid_res = ExtractU64(request, 1U);
    if (!slot_nid_res.has_value())
        return score::crypto::make_unexpected(slot_nid_res.error());

    auto ts_handle_res = m_service->ResolveTrustStoreForOperation(ctx.client_id, ts_nid_res.value());
    if (!ts_handle_res.has_value())
        return score::crypto::make_unexpected(ts_handle_res.error());
    auto slot_res = m_service->ResolveSlotForOperation(ctx.client_id, slot_nid_res.value());
    if (!slot_res.has_value())
        return score::crypto::make_unexpected(Error::kInvalidArgument);

    auto result = m_service->GetTrustStoreManager()->AcknowledgeMemberUpdate(
        ts_handle_res.value(), slot_res.value().handle, ctx.client_id);
    if (!result.has_value())
        return score::crypto::make_unexpected(result.error());
    return OkResponse();
}

// Parameter layout:
//   request[0] = ts_node_id (uint64)
//   request[1] = slot_node_id (uint64) — from MemberInfo::slot_id.id
//   request[2] = format (uint8)
//   request[3] = CRL bytes (span<const uint8_t>)
Expected<common::ResponseParameters, Error> TrustStoreManagementExecutor::HandleTrustStoreImportCrlForMember(
    const CertMgmtExecutionContext& ctx,
    common::RequestParameters& request)
{
    auto ts_nid_res = ExtractU64(request, 0U);
    if (!ts_nid_res.has_value())
        return score::crypto::make_unexpected(ts_nid_res.error());
    auto slot_nid_res = ExtractU64(request, 1U);
    if (!slot_nid_res.has_value())
        return score::crypto::make_unexpected(slot_nid_res.error());
    auto fmt_res = ExtractU8(request, 2U);
    if (!fmt_res.has_value())
        return score::crypto::make_unexpected(fmt_res.error());
    auto crl_res = ExtractBytes(request, 3U);
    if (!crl_res.has_value())
        return score::crypto::make_unexpected(crl_res.error());

    auto ts_handle_res = m_service->ResolveTrustStoreForOperation(ctx.client_id, ts_nid_res.value());
    if (!ts_handle_res.has_value())
        return score::crypto::make_unexpected(ts_handle_res.error());
    auto slot_res = m_service->ResolveSlotForOperation(ctx.client_id, slot_nid_res.value());
    if (!slot_res.has_value())
        return score::crypto::make_unexpected(Error::kInvalidArgument);

    // Load the slot's cert to validate the CRL is issued by the right CA.
    if (!m_cert_parser)
        return score::crypto::make_unexpected(Error::kInternalError);
    auto cert_res = m_service->GetSlotManager()->LoadCertificate(slot_res->handle, ctx.client_id);
    if (!cert_res.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleTrustStoreImportCrlForMember: slot has no certificate";
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }
    const auto format = static_cast<score::crypto::FormatType>(fmt_res.value());
    auto metadata_res = m_cert_parser->ValidateCrl(crl_res.value().data(),
                                                   crl_res.value().size(),
                                                   format,
                                                   cert_res.value()->GetRawBytes().data(),
                                                   cert_res.value()->GetRawBytes().size(),
                                                   cert_res.value()->GetFormat());
    if (!metadata_res.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleTrustStoreImportCrlForMember: CRL validation failed";
        return score::crypto::make_unexpected(metadata_res.error());
    }

    auto result = m_service->GetTrustStoreManager()->ImportCrlForMember(
        ts_handle_res.value(), slot_res.value().handle, crl_res.value(), format, ctx.client_id, *metadata_res);
    if (!result.has_value())
        return score::crypto::make_unexpected(result.error());
    return OkResponse();
}

Expected<common::ResponseParameters, Error> TrustStoreManagementExecutor::HandleTrustStoreDeleteCrlForMember(
    const CertMgmtExecutionContext& ctx,
    common::RequestParameters& request)
{
    auto ts_nid_res = ExtractU64(request, 0U);
    if (!ts_nid_res.has_value())
        return score::crypto::make_unexpected(ts_nid_res.error());
    auto slot_nid_res = ExtractU64(request, 1U);
    if (!slot_nid_res.has_value())
        return score::crypto::make_unexpected(slot_nid_res.error());

    auto ts_handle_res = m_service->ResolveTrustStoreForOperation(ctx.client_id, ts_nid_res.value());
    if (!ts_handle_res.has_value())
        return score::crypto::make_unexpected(ts_handle_res.error());
    auto slot_res = m_service->ResolveSlotForOperation(ctx.client_id, slot_nid_res.value());
    if (!slot_res.has_value())
        return score::crypto::make_unexpected(Error::kInvalidArgument);

    auto result = m_service->GetTrustStoreManager()->DeleteCrlForMember(
        ts_handle_res.value(), slot_res.value().handle, ctx.client_id);
    if (!result.has_value())
        return score::crypto::make_unexpected(result.error());
    return OkResponse();
}

}  // namespace score::crypto::daemon::provider::crypto_executor

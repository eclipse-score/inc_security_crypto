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

#include "score/crypto/src/daemon/provider/executors/cert_mgmt_executor.hpp"
#include "score/crypto/src/daemon/cert_management/query/cert_object_serializer.hpp"
#include "score/crypto/src/daemon/provider/cert_management/cert_management_operations.hpp"
#include "score/mw/log/logging.h"

#include <algorithm>
#include <cstdint>
#include <string_view>

namespace score::crypto::daemon::provider::crypto_executor
{

namespace
{
constexpr std::string_view LOG_PREFIX = "[CERT_MGMT_EXEC] ";
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

CertManagementExecutor::CertManagementExecutor(
    cert_management::ICertParser::Sptr cert_parser,
    std::shared_ptr<::score::crypto::daemon::cert_management::CertManagementService> service)
    : m_cert_parser{std::move(cert_parser)}, m_service{std::move(service)}
{
}

Expected<common::ResponseParameters, Error> CertManagementExecutor::Execute(
    const CertMgmtExecutionContext& ctx,
    const common::OperationIdentifier& operationId,
    common::RequestParameters& request)
{
    const auto action = operationId.operationAction;

    if (action == cm_ops::CERT_PARSE)
        return HandleParse(ctx, request);
    if (action == cm_ops::CERT_PARSE_CHAIN)
        return HandleParseChain(ctx, request);
    if (action == cm_ops::CERT_LOAD)
        return HandleLoad(ctx, request);
    if (action == cm_ops::CERT_SAVE)
        return HandleSave(ctx, request);
    if (action == cm_ops::CERT_EXPORT)
        return HandleExport(ctx, request);
    if (action == cm_ops::CERT_GET_EXPORT_SIZE)
        return HandleGetExportSize(ctx, request);
    if (action == cm_ops::CERT_CLEAR)
        return HandleClear(ctx, request);
    if (action == cm_ops::CERT_RELEASE)
        return HandleRelease(ctx, request);
    if (action == cm_ops::CRL_IMPORT || action == cm_ops::CRL_IMPORT_TO_SLOT)
        return HandleCrlImport(ctx, operationId, request);
    if (action == cm_ops::CRL_DELETE)
        return HandleCrlDelete(ctx, request);
    // Trust-store mutation ops (add/remove/enable/disable/ack-update/import-CRL-for-member)
    // are handled by TrustStoreManagementExecutor under the CERT:TRUST_STORE context.
    // Trust-store info queries go directly through the mediator's GET_TRUST_STORE_OBJECT op.

    // Provider-specific operations are handled by certificate context handlers.
    if ((action == cm_ops::CERT_CONVERT) || (action == cm_ops::CERT_GET_CONVERT_SIZE) ||
        (action == cm_ops::CERT_PUBLIC_KEY) || (action == cm_ops::OCSP_REQUEST))
    {
        score::mw::log::LogError() << LOG_PREFIX << "Operation 0x" << score::mw::log::LogHex16{action}
                                   << " is unavailable in the certificate management context";
        return score::crypto::make_unexpected(Error::kUnsupportedOperation);
    }

    score::mw::log::LogError() << LOG_PREFIX << "Unknown action 0x" << score::mw::log::LogHex16{action};
    return score::crypto::make_unexpected(Error::kUnsupportedOperation);
}

// ---------------------------------------------------------------------------
// Parse / chain parse
// ---------------------------------------------------------------------------

// Parameter layout:
//   request[0] = format (uint8: 0=DER, 1=PEM)
//   request[1] = cert bytes (span<const uint8_t>)
// Response: cert_node_id (uint64), provider_id (uint16)
Expected<common::ResponseParameters, Error> CertManagementExecutor::HandleParse(const CertMgmtExecutionContext& ctx,
                                                                                common::RequestParameters& request)
{
    if (!m_cert_parser)
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleParse: no cert parser available";
        return score::crypto::make_unexpected(Error::kInternalError);
    }
    auto fmt_res = ExtractU8(request, 0U);
    if (!fmt_res.has_value())
        return score::crypto::make_unexpected(fmt_res.error());
    auto bytes_res = ExtractBytes(request, 1U);
    if (!bytes_res.has_value())
        return score::crypto::make_unexpected(bytes_res.error());

    const auto format = static_cast<score::crypto::FormatType>(fmt_res.value());
    const auto& bytes = bytes_res.value();

    auto parse_res = m_cert_parser->ParseCertificate(bytes.data(), bytes.size(), format);
    if (!parse_res.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleParse: parse failed";
        return score::crypto::make_unexpected(parse_res.error());
    }

    ::score::crypto::daemon::cert_management::CertRegistrationParams params{ctx.client_id, ctx.context_node_id, {}};
    auto reg_res = m_service->RegisterCertMaterial(params, std::move(parse_res.value()));
    if (!reg_res.has_value())
        return score::crypto::make_unexpected(reg_res.error());

    common::ResponseParameters out;
    out.push_back(static_cast<std::uint64_t>(reg_res.value().node_id));
    out.push_back(static_cast<std::uint16_t>(ctx.provider_id));
    return out;
}

// Parameter layout: same as CERT_PARSE
// Response: N cert_node_ids (uint64 each); first value is the count.
Expected<common::ResponseParameters, Error> CertManagementExecutor::HandleParseChain(
    const CertMgmtExecutionContext& ctx,
    common::RequestParameters& request)
{
    if (!m_cert_parser)
        return score::crypto::make_unexpected(Error::kInternalError);

    auto fmt_res = ExtractU8(request, 0U);
    if (!fmt_res.has_value())
        return score::crypto::make_unexpected(fmt_res.error());
    auto bytes_res = ExtractBytes(request, 1U);
    if (!bytes_res.has_value())
        return score::crypto::make_unexpected(bytes_res.error());

    const auto format = static_cast<score::crypto::FormatType>(fmt_res.value());
    const auto& bytes = bytes_res.value();

    auto parse_res = m_cert_parser->ParseCertificates(bytes.data(), bytes.size(), format);
    if (!parse_res.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleParseChain: parse failed";
        return score::crypto::make_unexpected(parse_res.error());
    }

    auto& certs = parse_res.value();
    common::ResponseParameters out;
    out.push_back(static_cast<std::uint64_t>(certs.size()));
    for (auto& cert : certs)
    {
        ::score::crypto::daemon::cert_management::CertRegistrationParams params{ctx.client_id, ctx.context_node_id, {}};
        auto reg_res = m_service->RegisterCertMaterial(params, std::move(cert));
        if (!reg_res.has_value())
            return score::crypto::make_unexpected(reg_res.error());
        out.push_back(static_cast<std::uint64_t>(reg_res.value().node_id));
    }
    return out;
}

// ---------------------------------------------------------------------------
// Load from slot
// ---------------------------------------------------------------------------

// Parameter layout: request[0] = slot_node_id (uint64)
// Response: cert_node_id (uint64), provider_id (uint16)
Expected<common::ResponseParameters, Error> CertManagementExecutor::HandleLoad(const CertMgmtExecutionContext& ctx,
                                                                               common::RequestParameters& request)
{
    auto slot_nid_res = ExtractU64(request, 0U);
    if (!slot_nid_res.has_value())
        return score::crypto::make_unexpected(slot_nid_res.error());

    auto slot_res = m_service->ResolveSlotForOperation(ctx.client_id, slot_nid_res.value());
    if (!slot_res.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleLoad: slot resolution failed";
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }
    const auto& resolved = slot_res.value();

    ::score::crypto::daemon::cert_management::CertRegistrationParams params{
        ctx.client_id, ctx.context_node_id, resolved.handle};
    auto load_res = m_service->Load(params);
    if (!load_res.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleLoad: Load failed";
        return score::crypto::make_unexpected(load_res.error());
    }

    common::ResponseParameters out;
    out.push_back(static_cast<std::uint64_t>(load_res.value().node_id));
    out.push_back(static_cast<std::uint16_t>(ctx.provider_id));
    return out;
}

// ---------------------------------------------------------------------------
// Save to slot
// ---------------------------------------------------------------------------

// Parameter layout:
//   request[0] = slot_node_id (uint64)
//   request[1] = cert_node_id (uint64)
//   request[2] = with_crl (uint8, optional; 0=no CRL, 1=propagate CRL; default=0)
Expected<common::ResponseParameters, Error> CertManagementExecutor::HandleSave(const CertMgmtExecutionContext& ctx,
                                                                               common::RequestParameters& request)
{
    auto slot_nid_res = ExtractU64(request, 0U);
    if (!slot_nid_res.has_value())
        return score::crypto::make_unexpected(slot_nid_res.error());
    auto cert_nid_res = ExtractU64(request, 1U);
    if (!cert_nid_res.has_value())
        return score::crypto::make_unexpected(cert_nid_res.error());

    auto slot_res = m_service->ResolveSlotForOperation(ctx.client_id, slot_nid_res.value());
    if (!slot_res.has_value())
        return score::crypto::make_unexpected(Error::kInvalidArgument);

    auto cert_res = m_service->ResolveCertForOperation(ctx.client_id, cert_nid_res.value());
    if (!cert_res.has_value())
        return score::crypto::make_unexpected(cert_res.error());

    auto& slot_mgr = *m_service->GetSlotManager();
    auto store_res = slot_mgr.StoreCertificate(slot_res.value().handle, ctx.client_id, *cert_res.value());
    if (!store_res.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleSave: StoreCertificate failed";
        return score::crypto::make_unexpected(store_res.error());
    }
    m_service->NotifySlotCertChanged(slot_res.value().handle);

    // Optional CRL propagation: check with_crl flag at request[2].
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
                const auto& resolved_crl = *crl_res.value();
                const score::crypto::span<const uint8_t> crl_span(resolved_crl.bytes.data(), resolved_crl.bytes.size());
                const auto stored = slot_mgr.ImportCrl(
                    slot_res.value().handle, ctx.client_id, crl_span, resolved_crl.format, resolved_crl.metadata);
                if (!stored)
                    return score::crypto::make_unexpected(stored.error());
            }
        }
    }

    return OkResponse();
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

// Parameter layout:
//   request[0] = cert_node_id (uint64)
//   request[1] = desired format (uint8)
//   request[2] = output buffer (span<uint8_t>)
Expected<common::ResponseParameters, Error> CertManagementExecutor::HandleExport(const CertMgmtExecutionContext& ctx,
                                                                                 common::RequestParameters& request)
{
    if (request.size() < 3U)
        return score::crypto::make_unexpected(Error::kInsufficientParameters);

    auto cert_nid_res = ExtractU64(request, 0U);
    if (!cert_nid_res.has_value())
        return score::crypto::make_unexpected(cert_nid_res.error());
    auto format_res = ExtractU8(request, 1U);
    if (!format_res.has_value())
        return score::crypto::make_unexpected(format_res.error());

    auto cert_res = m_service->ResolveCertForOperation(ctx.client_id, cert_nid_res.value());
    if (!cert_res.has_value())
        return score::crypto::make_unexpected(cert_res.error());
    if (!m_cert_parser)
        return score::crypto::make_unexpected(Error::kInternalError);

    const auto encoded =
        m_cert_parser->EncodeCertificate(*cert_res.value(), static_cast<score::crypto::FormatType>(format_res.value()));
    if (!encoded.has_value())
        return score::crypto::make_unexpected(encoded.error());

    auto* output = std::get_if<score::crypto::span<uint8_t>>(&request[2]);
    if (output == nullptr || output->data() == nullptr || output->size() == 0U || output->size() < encoded->size())
        return score::crypto::make_unexpected(Error::kInsufficientBufferSize);

    std::copy(encoded->begin(), encoded->end(), output->begin());

    common::ResponseParameters out;
    out.push_back(static_cast<std::uint64_t>(encoded->size()));
    return out;
}

// Parameter layout: same as CERT_EXPORT
Expected<common::ResponseParameters, Error> CertManagementExecutor::HandleGetExportSize(
    const CertMgmtExecutionContext& ctx,
    common::RequestParameters& request)
{
    auto cert_nid_res = ExtractU64(request, 0U);
    if (!cert_nid_res.has_value())
        return score::crypto::make_unexpected(cert_nid_res.error());
    auto format_res = ExtractU8(request, 1U);
    if (!format_res.has_value())
        return score::crypto::make_unexpected(format_res.error());

    auto cert_res = m_service->ResolveCertForOperation(ctx.client_id, cert_nid_res.value());
    if (!cert_res.has_value())
        return score::crypto::make_unexpected(cert_res.error());
    if (!m_cert_parser)
        return score::crypto::make_unexpected(Error::kInternalError);

    const auto encoded =
        m_cert_parser->EncodeCertificate(*cert_res.value(), static_cast<score::crypto::FormatType>(format_res.value()));
    if (!encoded.has_value())
        return score::crypto::make_unexpected(encoded.error());

    common::ResponseParameters out;
    out.push_back(static_cast<std::uint64_t>(encoded->size()));
    return out;
}

// ---------------------------------------------------------------------------
// Clear slot
// ---------------------------------------------------------------------------

// Parameter layout: request[0] = slot_node_id (uint64)
Expected<common::ResponseParameters, Error> CertManagementExecutor::HandleClear(const CertMgmtExecutionContext& ctx,
                                                                                common::RequestParameters& request)
{
    auto slot_nid_res = ExtractU64(request, 0U);
    if (!slot_nid_res.has_value())
        return score::crypto::make_unexpected(slot_nid_res.error());

    auto slot_res = m_service->ResolveSlotForOperation(ctx.client_id, slot_nid_res.value());
    if (!slot_res.has_value())
        return score::crypto::make_unexpected(Error::kInvalidArgument);

    auto clear_res = m_service->GetSlotManager()->ClearSlot(slot_res.value().handle, ctx.client_id);
    if (!clear_res.has_value())
        return score::crypto::make_unexpected(clear_res.error());
    m_service->NotifySlotCertChanged(slot_res.value().handle);
    return OkResponse();
}

// ---------------------------------------------------------------------------
// Release cert data node
// ---------------------------------------------------------------------------

// Parameter layout: request[0] = cert_node_id (uint64)
Expected<common::ResponseParameters, Error> CertManagementExecutor::HandleRelease(const CertMgmtExecutionContext& ctx,
                                                                                  common::RequestParameters& request)
{
    auto cert_nid_res = ExtractU64(request, 0U);
    if (!cert_nid_res.has_value())
        return score::crypto::make_unexpected(cert_nid_res.error());

    auto rel_res = m_service->ReleaseCert(ctx.client_id, cert_nid_res.value());
    if (!rel_res.has_value())
        return score::crypto::make_unexpected(rel_res.error());
    return OkResponse();
}

// ---------------------------------------------------------------------------
// CRL operations
// ---------------------------------------------------------------------------

// Parameter layout:
//   request[0] = target_node_id (uint64) — CertDataNode for CRL_IMPORT,
//                CertSlotDataNode for CRL_IMPORT_TO_SLOT
//   request[1] = format (uint8)
//   request[2] = CRL bytes (span<const uint8_t>)
Expected<common::ResponseParameters, Error> CertManagementExecutor::HandleCrlImport(
    const CertMgmtExecutionContext& ctx,
    const common::OperationIdentifier& operation_id,
    common::RequestParameters& request)
{
    auto nid_res = ExtractU64(request, 0U);
    if (!nid_res.has_value())
        return score::crypto::make_unexpected(nid_res.error());
    auto fmt_res = ExtractU8(request, 1U);
    if (!fmt_res.has_value())
        return score::crypto::make_unexpected(fmt_res.error());
    auto bytes_res = ExtractBytes(request, 2U);
    if (!bytes_res.has_value())
        return score::crypto::make_unexpected(bytes_res.error());

    const auto format = static_cast<score::crypto::FormatType>(fmt_res.value());
    const auto& crl_bytes = bytes_res.value();

    if (operation_id.operationAction == cm_ops::CRL_IMPORT)
    {
        // Session-scoped: target is a CertDataNode; validate CRL against the cert, then store in-memory.
        if (!m_cert_parser)
            return score::crypto::make_unexpected(Error::kInternalError);
        auto cert_res = m_service->ResolveCertForOperation(ctx.client_id, nid_res.value());
        if (!cert_res.has_value())
            return score::crypto::make_unexpected(cert_res.error());
        auto metadata_res = m_cert_parser->ValidateCrl(crl_bytes.data(),
                                                       crl_bytes.size(),
                                                       format,
                                                       cert_res.value()->GetRawBytes().data(),
                                                       cert_res.value()->GetRawBytes().size(),
                                                       cert_res.value()->GetFormat());
        if (!metadata_res.has_value())
        {
            score::mw::log::LogError() << LOG_PREFIX << "HandleCrlImport: CRL validation failed (session)";
            return score::crypto::make_unexpected(metadata_res.error());
        }
        auto entry_res = m_service->ResolveCertEntryForOperation(ctx.client_id, nid_res.value());
        if (!entry_res.has_value())
            return score::crypto::make_unexpected(entry_res.error());
        std::vector<uint8_t> crl_vec(crl_bytes.begin(), crl_bytes.end());
        entry_res.value()->AttachSessionCrl(std::move(crl_vec), format, *metadata_res);
        return OkResponse();
    }

    // Persistent: target is a CertSlotDataNode; write CRL to slot's [crl] section.
    auto slot_res = m_service->ResolveSlotForOperation(ctx.client_id, nid_res.value());
    if (!slot_res.has_value())
        return score::crypto::make_unexpected(Error::kInvalidArgument);

    // Load the slot's cert to validate the CRL is issued by the right CA.
    if (!m_cert_parser)
        return score::crypto::make_unexpected(Error::kInternalError);
    auto cert_res = m_service->GetSlotManager()->LoadCertificate(slot_res->handle, ctx.client_id);
    if (!cert_res.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleCrlImport: slot has no certificate to validate against";
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }
    auto metadata_res = m_cert_parser->ValidateCrl(crl_bytes.data(),
                                                   crl_bytes.size(),
                                                   format,
                                                   cert_res.value()->GetRawBytes().data(),
                                                   cert_res.value()->GetRawBytes().size(),
                                                   cert_res.value()->GetFormat());
    if (!metadata_res.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "HandleCrlImport: CRL validation failed";
        return score::crypto::make_unexpected(metadata_res.error());
    }

    auto store_res =
        m_service->GetSlotManager()->ImportCrl(slot_res->handle, ctx.client_id, crl_bytes, format, *metadata_res);
    if (!store_res.has_value())
        return score::crypto::make_unexpected(store_res.error());
    return OkResponse();
}

// Parameter layout: request[0] = slot_node_id (uint64)
Expected<common::ResponseParameters, Error> CertManagementExecutor::HandleCrlDelete(const CertMgmtExecutionContext& ctx,
                                                                                    common::RequestParameters& request)
{
    auto slot_nid_res = ExtractU64(request, 0U);
    if (!slot_nid_res.has_value())
        return score::crypto::make_unexpected(slot_nid_res.error());

    auto slot_res = m_service->ResolveSlotForOperation(ctx.client_id, slot_nid_res.value());
    if (!slot_res.has_value())
        return score::crypto::make_unexpected(Error::kInvalidArgument);

    auto del_res = m_service->GetSlotManager()->DeleteCrl(slot_res.value().handle, ctx.client_id);
    if (!del_res.has_value())
        return score::crypto::make_unexpected(del_res.error());
    return OkResponse();
}

}  // namespace score::crypto::daemon::provider::crypto_executor

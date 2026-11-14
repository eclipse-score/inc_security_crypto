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

#include "score/crypto/src/daemon/cert_management/context/management/executor.hpp"

#include "score/crypto/src/daemon/cert_management/context/crl_validation.hpp"
#include "score/crypto/src/daemon/cert_management/core/cert_entry.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_management_operations.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_types.hpp"
#include "score/mw/log/logging.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <utility>
#include <vector>

namespace score::crypto::daemon::cert_management
{

namespace
{

constexpr std::string_view kLogPrefix = "[CERT_MGMT_EXEC] ";
namespace cm_ops = ::score::crypto::daemon::cert_management::operations;
using Error = common::DaemonErrorCode;
using Response = score::crypto::Expected<common::ResponseParameters, Error>;

/// Extract a scalar of type T at index; fails when the parameter is missing or has another type.
template <typename T>
score::crypto::Expected<T, Error> ExtractValue(const common::RequestParameters& request, std::size_t index)
{
    if (request.size() <= index)
    {
        return score::crypto::make_unexpected(Error::kInsufficientParameters);
    }
    const auto* value = std::get_if<T>(&request[index]);
    if (value == nullptr)
    {
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }
    return *value;
}

/// Extract a read-only byte buffer at index.
score::crypto::Expected<score::crypto::span<const std::uint8_t>, Error> ExtractBytes(
    const common::RequestParameters& request,
    std::size_t index)
{
    if (request.size() <= index)
    {
        return score::crypto::make_unexpected(Error::kInsufficientParameters);
    }
    const auto* value = std::get_if<score::crypto::span<const std::uint8_t>>(&request[index]);
    if (value == nullptr)
    {
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }
    return *value;
}

common::ResponseParameters OkResponse()
{
    common::ResponseParameters out;
    out.push_back(static_cast<std::uint64_t>(0U));
    return out;
}

}  // namespace

CertManagementExecutor::CertManagementExecutor(provider::cert_management::ICertParser::Sptr cert_parser,
                                               CertManagementService::Sptr service)
    : m_cert_parser{std::move(cert_parser)}, m_service{std::move(service)}
{
}

score::crypto::Expected<common::ResponseParameters, Error> CertManagementExecutor::Execute(
    const CertExecutionContext& ctx,
    const common::OperationIdentifier& operation_id,
    common::RequestParameters& request) const
{
    const auto action = operation_id.operationAction;

    if (action == cm_ops::CERT_PARSE)
    {
        return HandleParse(ctx, request);
    }
    if (action == cm_ops::CERT_PARSE_CHAIN)
    {
        return HandleParseChain(ctx, request);
    }
    if (action == cm_ops::CERT_LOAD)
    {
        return HandleLoad(ctx, request);
    }
    if (action == cm_ops::CERT_SAVE)
    {
        return HandleSave(ctx, request);
    }
    if (action == cm_ops::CERT_EXPORT)
    {
        return HandleExport(ctx, request);
    }
    if (action == cm_ops::CERT_GET_EXPORT_SIZE)
    {
        return HandleGetExportSize(ctx, request);
    }
    if (action == cm_ops::CERT_CLEAR)
    {
        return HandleClear(ctx, request);
    }
    if (action == cm_ops::CERT_RELEASE)
    {
        return HandleRelease(ctx, request);
    }
    if (action == cm_ops::CRL_IMPORT)
    {
        return HandleCrlImportToCertificate(ctx, request);
    }
    if (action == cm_ops::CRL_IMPORT_TO_SLOT)
    {
        return HandleCrlImportToSlot(ctx, request);
    }
    if (action == cm_ops::CRL_DELETE)
    {
        return HandleCrlDelete(ctx, request);
    }

    if (action == cm_ops::CERT_CONVERT)
    {
        return HandleConvert(ctx, request);
    }
    if (action == cm_ops::CERT_GET_CONVERT_SIZE)
    {
        return HandleGetConvertSize(ctx, request);
    }

    // Trust-store operations are served by the CERT:TRUST_STORE context. Public-key extraction and OCSP are not
    // served by this context.
    if (action == cm_ops::CERT_LOAD_PUBLIC_KEY || action == cm_ops::OCSP_REQUEST)
    {
        score::mw::log::LogError() << kLogPrefix << "Operation 0x" << score::mw::log::LogHex16{action}
                                   << " is unavailable in the certificate management context";
        return score::crypto::make_unexpected(Error::kUnsupportedOperation);
    }

    score::mw::log::LogError() << kLogPrefix << "Unknown action 0x" << score::mw::log::LogHex16{action};
    return score::crypto::make_unexpected(Error::kUnsupportedOperation);
}

// ---------------------------------------------------------------------------
// Parse
// ---------------------------------------------------------------------------

// Parameter layout:
//   request[0] = format (uint8)
//   request[1] = certificate bytes (span<const uint8_t>)
// Response: certificate node id (uint64), provider id (uint16)
Response CertManagementExecutor::HandleParse(const CertExecutionContext& ctx, common::RequestParameters& request) const
{
    const auto format = ExtractValue<std::uint8_t>(request, 0U);
    if (!format.has_value())
    {
        return score::crypto::make_unexpected(format.error());
    }
    const auto bytes = ExtractBytes(request, 1U);
    if (!bytes.has_value())
    {
        return score::crypto::make_unexpected(bytes.error());
    }

    auto parsed = m_cert_parser->ParseCertificate(
        bytes.value().data(), bytes.value().size(), static_cast<score::crypto::FormatType>(format.value()));
    if (!parsed.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "HandleParse: parse failed";
        return score::crypto::make_unexpected(parsed.error());
    }

    auto registered = m_service->RegisterCertificate(CertRegistrationParams{ctx.client_id, ctx.context_node_id, {}},
                                                     std::move(parsed.value()));
    if (!registered.has_value())
    {
        return score::crypto::make_unexpected(registered.error());
    }

    common::ResponseParameters out;
    out.push_back(static_cast<std::uint64_t>(registered.value().node_id));
    out.push_back(static_cast<std::uint16_t>(ctx.provider_id));
    return out;
}

// Parameter layout: same as CERT_PARSE
// Response: certificate count (uint64) followed by one certificate node id (uint64) per certificate.
Response CertManagementExecutor::HandleParseChain(const CertExecutionContext& ctx,
                                                  common::RequestParameters& request) const
{
    const auto format = ExtractValue<std::uint8_t>(request, 0U);
    if (!format.has_value())
    {
        return score::crypto::make_unexpected(format.error());
    }
    const auto bytes = ExtractBytes(request, 1U);
    if (!bytes.has_value())
    {
        return score::crypto::make_unexpected(bytes.error());
    }

    auto parsed = m_cert_parser->ParseCertificates(
        bytes.value().data(), bytes.value().size(), static_cast<score::crypto::FormatType>(format.value()));
    if (!parsed.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "HandleParseChain: parse failed";
        return score::crypto::make_unexpected(parsed.error());
    }

    common::ResponseParameters out;
    out.push_back(static_cast<std::uint64_t>(parsed.value().size()));
    for (auto& certificate : parsed.value())
    {
        auto registered = m_service->RegisterCertificate(CertRegistrationParams{ctx.client_id, ctx.context_node_id, {}},
                                                         std::move(certificate));
        if (!registered.has_value())
        {
            return score::crypto::make_unexpected(registered.error());
        }
        out.push_back(static_cast<std::uint64_t>(registered.value().node_id));
    }
    return out;
}

// ---------------------------------------------------------------------------
// Load from slot
// ---------------------------------------------------------------------------

// Parameter layout: request[0] = slot node id (uint64)
// Response: certificate node id (uint64), provider id (uint16)
Response CertManagementExecutor::HandleLoad(const CertExecutionContext& ctx, common::RequestParameters& request) const
{
    const auto slot_node = ExtractValue<std::uint64_t>(request, 0U);
    if (!slot_node.has_value())
    {
        return score::crypto::make_unexpected(slot_node.error());
    }

    const auto slot = m_service->ResolveCertSlotHandle(ctx.client_id, slot_node.value());
    if (!slot.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "HandleLoad: slot resolution failed";
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }

    auto loaded = m_service->LoadCertificate(CertRegistrationParams{ctx.client_id, ctx.context_node_id, slot.value()});
    if (!loaded.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "HandleLoad: load failed";
        return score::crypto::make_unexpected(loaded.error());
    }

    common::ResponseParameters out;
    out.push_back(static_cast<std::uint64_t>(loaded.value().node_id));
    out.push_back(static_cast<std::uint16_t>(ctx.provider_id));
    return out;
}

// ---------------------------------------------------------------------------
// Save to slot
// ---------------------------------------------------------------------------

// Parameter layout:
//   request[0] = slot node id (uint64)
//   request[1] = certificate node id (uint64)
//   request[2] = with_crl (uint8, optional; 0 = no CRL, nonzero = propagate the certificate's CRL)
// The certificate write discards the slot's previous CRL. A propagated CRL is written after it.
Response CertManagementExecutor::HandleSave(const CertExecutionContext& ctx, common::RequestParameters& request) const
{
    const auto slot_node = ExtractValue<std::uint64_t>(request, 0U);
    if (!slot_node.has_value())
    {
        return score::crypto::make_unexpected(slot_node.error());
    }
    const auto cert_node = ExtractValue<std::uint64_t>(request, 1U);
    if (!cert_node.has_value())
    {
        return score::crypto::make_unexpected(cert_node.error());
    }

    const auto slot = m_service->ResolveCertSlotHandle(ctx.client_id, slot_node.value());
    if (!slot.has_value())
    {
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }

    auto certificate = m_service->ResolveCertObject(ctx.client_id, cert_node.value());
    if (!certificate.has_value())
    {
        return score::crypto::make_unexpected(certificate.error());
    }

    const auto stored = m_service->UpdateSlot(slot.value(), ctx.client_id, *certificate.value());
    if (!stored.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "HandleSave: slot write failed";
        return score::crypto::make_unexpected(stored.error());
    }

    if (request.size() > 2U)
    {
        const auto with_crl = ExtractValue<std::uint8_t>(request, 2U);
        if (!with_crl.has_value())
        {
            return score::crypto::make_unexpected(with_crl.error());
        }
        if (with_crl.value() != 0U)
        {
            auto crl = m_service->ResolveCrlData(ctx.client_id, cert_node.value());
            if (!crl.has_value())
            {
                return score::crypto::make_unexpected(crl.error());
            }
            if (crl.value())
            {
                const auto propagated = m_service->UpdateSlot(slot.value(), ctx.client_id, *crl.value());
                if (!propagated.has_value())
                {
                    return score::crypto::make_unexpected(propagated.error());
                }
            }
        }
    }

    return OkResponse();
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

// Parameter layout:
//   request[0] = certificate node id (uint64)
//   request[1] = desired format (uint8)
//   request[2] = output buffer (span<uint8_t>)
// Response: encoded size (uint64)
Response CertManagementExecutor::HandleExport(const CertExecutionContext& ctx, common::RequestParameters& request) const
{
    if (request.size() < 3U)
    {
        return score::crypto::make_unexpected(Error::kInsufficientParameters);
    }

    auto encoded = EncodeCertificateNode(ctx, request);
    if (!encoded.has_value())
    {
        return score::crypto::make_unexpected(encoded.error());
    }

    auto* output = std::get_if<score::crypto::span<std::uint8_t>>(&request[2]);
    if (output == nullptr || output->data() == nullptr || output->size() == 0U || output->size() < encoded->size())
    {
        return score::crypto::make_unexpected(Error::kInsufficientBufferSize);
    }

    std::copy(encoded->begin(), encoded->end(), output->begin());

    common::ResponseParameters out;
    out.push_back(static_cast<std::uint64_t>(encoded->size()));
    return out;
}

// Parameter layout: request[0] = certificate node id (uint64), request[1] = format (uint8)
// Response: encoded size (uint64)
Response CertManagementExecutor::HandleGetExportSize(const CertExecutionContext& ctx,
                                                     common::RequestParameters& request) const
{
    auto encoded = EncodeCertificateNode(ctx, request);
    if (!encoded.has_value())
    {
        return score::crypto::make_unexpected(encoded.error());
    }

    common::ResponseParameters out;
    out.push_back(static_cast<std::uint64_t>(encoded->size()));
    return out;
}

// Parameter layout for both conversion operations:
//   request[0] = input format (uint8)
//   request[1] = output format (uint8)
//   request[2] = input certificate bytes (span<const uint8_t>), a single certificate
// CERT_GET_CONVERT_SIZE response: converted size (uint64)
// CERT_CONVERT response: converted size (uint64); the converted bytes are written to request[3]
score::crypto::Expected<std::vector<std::uint8_t>, Error> CertManagementExecutor::ConvertCertificateBytes(
    const common::RequestParameters& request) const
{
    const auto input_format = ExtractValue<std::uint8_t>(request, 0U);
    if (!input_format.has_value())
    {
        return score::crypto::make_unexpected(input_format.error());
    }
    const auto output_format = ExtractValue<std::uint8_t>(request, 1U);
    if (!output_format.has_value())
    {
        return score::crypto::make_unexpected(output_format.error());
    }
    const auto input = ExtractBytes(request, 2U);
    if (!input.has_value())
    {
        return score::crypto::make_unexpected(input.error());
    }

    auto parsed = m_cert_parser->ParseCertificate(
        input.value().data(), input.value().size(), static_cast<score::crypto::FormatType>(input_format.value()));
    if (!parsed.has_value())
    {
        return score::crypto::make_unexpected(parsed.error());
    }
    return m_cert_parser->EncodeCertificate(*parsed.value(),
                                            static_cast<score::crypto::FormatType>(output_format.value()));
}

Response CertManagementExecutor::HandleConvert(const CertExecutionContext& /*ctx*/,
                                               common::RequestParameters& request) const
{
    if (request.size() < 4U)
    {
        return score::crypto::make_unexpected(Error::kInsufficientParameters);
    }

    auto converted = ConvertCertificateBytes(request);
    if (!converted.has_value())
    {
        return score::crypto::make_unexpected(converted.error());
    }

    auto* output = std::get_if<score::crypto::span<std::uint8_t>>(&request[3]);
    if (output == nullptr || output->data() == nullptr || output->size() == 0U || output->size() < converted->size())
    {
        return score::crypto::make_unexpected(Error::kInsufficientBufferSize);
    }

    std::copy(converted->begin(), converted->end(), output->begin());

    common::ResponseParameters out;
    out.push_back(static_cast<std::uint64_t>(converted->size()));
    return out;
}

Response CertManagementExecutor::HandleGetConvertSize(const CertExecutionContext& /*ctx*/,
                                                      common::RequestParameters& request) const
{
    auto converted = ConvertCertificateBytes(request);
    if (!converted.has_value())
    {
        return score::crypto::make_unexpected(converted.error());
    }

    common::ResponseParameters out;
    out.push_back(static_cast<std::uint64_t>(converted->size()));
    return out;
}

score::crypto::Expected<std::vector<std::uint8_t>, Error> CertManagementExecutor::EncodeCertificateNode(
    const CertExecutionContext& ctx,
    const common::RequestParameters& request) const
{
    const auto cert_node = ExtractValue<std::uint64_t>(request, 0U);
    if (!cert_node.has_value())
    {
        return score::crypto::make_unexpected(cert_node.error());
    }
    const auto format = ExtractValue<std::uint8_t>(request, 1U);
    if (!format.has_value())
    {
        return score::crypto::make_unexpected(format.error());
    }

    auto certificate = m_service->ResolveCertObject(ctx.client_id, cert_node.value());
    if (!certificate.has_value())
    {
        return score::crypto::make_unexpected(certificate.error());
    }

    return m_cert_parser->EncodeCertificate(*certificate.value(),
                                            static_cast<score::crypto::FormatType>(format.value()));
}

// ---------------------------------------------------------------------------
// Clear slot
// ---------------------------------------------------------------------------

// Parameter layout: request[0] = slot node id (uint64)
Response CertManagementExecutor::HandleClear(const CertExecutionContext& ctx, common::RequestParameters& request) const
{
    const auto slot_node = ExtractValue<std::uint64_t>(request, 0U);
    if (!slot_node.has_value())
    {
        return score::crypto::make_unexpected(slot_node.error());
    }

    const auto slot = m_service->ResolveCertSlotHandle(ctx.client_id, slot_node.value());
    if (!slot.has_value())
    {
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }

    const auto cleared = m_service->ClearSlot(slot.value(), ctx.client_id);
    if (!cleared.has_value())
    {
        return score::crypto::make_unexpected(cleared.error());
    }
    return OkResponse();
}

// ---------------------------------------------------------------------------
// Release certificate data node
// ---------------------------------------------------------------------------

// Parameter layout: request[0] = certificate node id (uint64)
Response CertManagementExecutor::HandleRelease(const CertExecutionContext& ctx,
                                               common::RequestParameters& request) const
{
    const auto cert_node = ExtractValue<std::uint64_t>(request, 0U);
    if (!cert_node.has_value())
    {
        return score::crypto::make_unexpected(cert_node.error());
    }

    const auto released = m_service->ReleaseCertificate(ctx.client_id, cert_node.value());
    if (!released.has_value())
    {
        return score::crypto::make_unexpected(released.error());
    }
    return OkResponse();
}

// ---------------------------------------------------------------------------
// CRL import
// ---------------------------------------------------------------------------

// Parameter layout for both CRL import operations:
//   request[0] = target node id (uint64): certificate node for CRL_IMPORT (session scope),
//                certificate slot node for CRL_IMPORT_TO_SLOT (persistent scope)
//   request[1] = CRL format (uint8)
//   request[2] = CRL bytes (span<const uint8_t>)
score::crypto::Expected<CertManagementExecutor::CrlImportParams, Error> CertManagementExecutor::ParseCrlImportParams(
    common::RequestParameters& request)
{
    const auto node = ExtractValue<std::uint64_t>(request, 0U);
    if (!node.has_value())
    {
        return score::crypto::make_unexpected(node.error());
    }
    const auto format = ExtractValue<std::uint8_t>(request, 1U);
    if (!format.has_value())
    {
        return score::crypto::make_unexpected(format.error());
    }
    const auto crl_bytes = ExtractBytes(request, 2U);
    if (!crl_bytes.has_value())
    {
        return score::crypto::make_unexpected(crl_bytes.error());
    }
    return CrlImportParams{node.value(), static_cast<score::crypto::FormatType>(format.value()), crl_bytes.value()};
}

Response CertManagementExecutor::HandleCrlImportToCertificate(const CertExecutionContext& ctx,
                                                              common::RequestParameters& request) const
{
    const auto params = ParseCrlImportParams(request);
    if (!params.has_value())
    {
        return score::crypto::make_unexpected(params.error());
    }
    const auto& crl_import = params.value();

    // Session scope: validate against the certificate, then attach to the certificate instance in memory.
    auto certificate = m_service->ResolveCertObject(ctx.client_id, crl_import.node_id);
    if (!certificate.has_value())
    {
        return score::crypto::make_unexpected(certificate.error());
    }
    auto crl = ValidateCrlAgainstIssuer(*m_cert_parser, *certificate.value(), crl_import.crl_bytes, crl_import.format);
    if (!crl.has_value())
    {
        return score::crypto::make_unexpected(crl.error());
    }
    auto entry = m_service->ResolveCertEntry(ctx.client_id, crl_import.node_id);
    if (!entry.has_value())
    {
        return score::crypto::make_unexpected(entry.error());
    }
    entry.value()->AttachSessionCrl(std::move(crl.value()));
    return OkResponse();
}

Response CertManagementExecutor::HandleCrlImportToSlot(const CertExecutionContext& ctx,
                                                       common::RequestParameters& request) const
{
    const auto params = ParseCrlImportParams(request);
    if (!params.has_value())
    {
        return score::crypto::make_unexpected(params.error());
    }
    const auto& crl_import = params.value();

    // Persistent scope: validate against the slot's certificate, then write the CRL to the slot.
    const auto slot = m_service->ResolveCertSlotHandle(ctx.client_id, crl_import.node_id);
    if (!slot.has_value())
    {
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }

    const auto slot_manager = m_service->GetSlotManager();
    if (!slot_manager)
    {
        score::mw::log::LogError() << kLogPrefix << "HandleCrlImportToSlot: no slot manager configured";
        return score::crypto::make_unexpected(Error::kInternalError);
    }
    auto issuer = slot_manager->LoadCertificate(slot.value(), ctx.client_id);
    if (!issuer.has_value())
    {
        score::mw::log::LogError() << kLogPrefix
                                   << "HandleCrlImportToSlot: slot has no certificate to validate against";
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }

    auto crl = ValidateCrlAgainstIssuer(*m_cert_parser, *issuer.value(), crl_import.crl_bytes, crl_import.format);
    if (!crl.has_value())
    {
        return score::crypto::make_unexpected(crl.error());
    }

    const auto stored = m_service->UpdateSlot(slot.value(), ctx.client_id, crl.value());
    if (!stored.has_value())
    {
        return score::crypto::make_unexpected(stored.error());
    }
    return OkResponse();
}

// ---------------------------------------------------------------------------
// CRL delete
// ---------------------------------------------------------------------------

// Parameter layout: request[0] = slot node id (uint64)
Response CertManagementExecutor::HandleCrlDelete(const CertExecutionContext& ctx,
                                                 common::RequestParameters& request) const
{
    const auto slot_node = ExtractValue<std::uint64_t>(request, 0U);
    if (!slot_node.has_value())
    {
        return score::crypto::make_unexpected(slot_node.error());
    }

    const auto slot = m_service->ResolveCertSlotHandle(ctx.client_id, slot_node.value());
    if (!slot.has_value())
    {
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }

    const auto cleared = m_service->ClearSlotCrl(slot.value(), ctx.client_id);
    if (!cleared.has_value())
    {
        return score::crypto::make_unexpected(cleared.error());
    }
    return OkResponse();
}

}  // namespace score::crypto::daemon::cert_management

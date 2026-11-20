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

#include "score/crypto/src/daemon/cert_management/context/trust_store/executor.hpp"

#include "score/crypto/src/daemon/cert_management/context/crl_validation.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_management_operations.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_types.hpp"
#include "score/mw/log/logging.h"

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <utility>
#include <vector>

namespace score::crypto::daemon::cert_management
{

namespace
{

constexpr std::string_view kLogPrefix{"[TRUST_STORE_EXEC] "};
namespace tsm_ops = ::score::crypto::daemon::cert_management::operations;
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

/// Extract a SHA-256 fingerprint at index; the buffer must be exactly kSha256FingerprintSize bytes.
score::crypto::Expected<score::crypto::span<const std::uint8_t>, Error> ExtractFingerprint(
    const common::RequestParameters& request,
    std::size_t index)
{
    auto bytes = ExtractBytes(request, index);
    if (!bytes.has_value())
    {
        return score::crypto::make_unexpected(bytes.error());
    }
    if (bytes.value().size() != score::crypto::kSha256FingerprintSize)
    {
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }
    return bytes.value();
}

common::ResponseParameters OkResponse()
{
    common::ResponseParameters out;
    out.push_back(static_cast<std::uint64_t>(0U));
    return out;
}

}  // namespace

TrustStoreManagementExecutor::TrustStoreManagementExecutor(provider::cert_management::ICertParser::Sptr cert_parser,
                                                           CertManagementService::Sptr service)
    : m_cert_parser{std::move(cert_parser)}, m_service{std::move(service)}
{
}

Response TrustStoreManagementExecutor::Execute(const CertExecutionContext& ctx,
                                               const common::OperationIdentifier& operation_id,
                                               common::RequestParameters& request) const
{
    switch (operation_id.operationAction)
    {
        case tsm_ops::TRUST_STORE_ADD_CERT:
            return HandleAddMember(ctx, request);
        case tsm_ops::TRUST_STORE_REMOVE_CERT:
            return HandleRemoveMember(ctx, request);
        case tsm_ops::TRUST_STORE_REMOVE_CERT_BY_ID:
            return HandleRemoveMemberById(ctx, request);
        case tsm_ops::TRUST_STORE_ENABLE_CERT:
            return HandleEnableMember(ctx, request);
        case tsm_ops::TRUST_STORE_DISABLE_CERT:
            return HandleDisableMember(ctx, request);
        case tsm_ops::TRUST_STORE_ACK_UPDATE:
            return HandleAcknowledgeMemberUpdate(ctx, request);
        case tsm_ops::TRUST_STORE_IMPORT_CRL_FOR_MEMBER:
            return HandleImportCrlForMember(ctx, request);
        case tsm_ops::TRUST_STORE_DELETE_CRL_FOR_MEMBER:
            return HandleDeleteCrlForMember(ctx, request);
        default:
            break;
    }
    score::mw::log::LogError() << kLogPrefix << "Unsupported action 0x"
                               << score::mw::log::LogHex16{operation_id.operationAction};
    return score::crypto::make_unexpected(Error::kUnsupportedOperation);
}

// Parameter layout:
//   request[0] = trust-store node id (uint64)
//   request[1] = certificate node id (uint64)
//   request[2] = with_crl flag (uint8, optional; non-zero attaches the certificate's CRL)
Response TrustStoreManagementExecutor::HandleAddMember(const CertExecutionContext& ctx,
                                                       common::RequestParameters& request) const
{
    const auto ts_node = ExtractValue<std::uint64_t>(request, 0U);
    if (!ts_node.has_value())
    {
        return score::crypto::make_unexpected(ts_node.error());
    }
    const auto cert_node = ExtractValue<std::uint64_t>(request, 1U);
    if (!cert_node.has_value())
    {
        return score::crypto::make_unexpected(cert_node.error());
    }

    const auto trust_store = m_service->ResolveTrustStoreHandle(ctx.client_id, ts_node.value());
    if (!trust_store.has_value())
    {
        return score::crypto::make_unexpected(trust_store.error());
    }
    const auto cert = m_service->ResolveCertObject(ctx.client_id, cert_node.value());
    if (!cert.has_value())
    {
        return score::crypto::make_unexpected(cert.error());
    }

    // A null CRL means none is attached; no default encoding is substituted.
    CrlData::Sptrc crl;
    if (request.size() > 2U)
    {
        const auto with_crl = ExtractValue<std::uint8_t>(request, 2U);
        if (!with_crl.has_value())
        {
            return score::crypto::make_unexpected(with_crl.error());
        }
        if (with_crl.value() != 0U)
        {
            auto resolved = m_service->ResolveCrlData(ctx.client_id, cert_node.value());
            if (!resolved.has_value())
            {
                return score::crypto::make_unexpected(resolved.error());
            }
            crl = resolved.value();
        }
    }

    const auto result =
        m_service->GetTrustStoreManager()->AddMember(trust_store.value(), cert.value(), ctx.client_id, std::move(crl));
    if (!result.has_value())
    {
        return score::crypto::make_unexpected(result.error());
    }
    return OkResponse();
}

// Parameter layout:
//   request[0] = trust-store node id (uint64)
//   request[1] = SHA-256 fingerprint of the member certificate (32 bytes)
Response TrustStoreManagementExecutor::HandleRemoveMember(const CertExecutionContext& ctx,
                                                          common::RequestParameters& request) const
{
    const auto ts_node = ExtractValue<std::uint64_t>(request, 0U);
    if (!ts_node.has_value())
    {
        return score::crypto::make_unexpected(ts_node.error());
    }
    const auto fingerprint_res = ExtractFingerprint(request, 1U);
    if (!fingerprint_res.has_value())
    {
        return score::crypto::make_unexpected(fingerprint_res.error());
    }

    const auto trust_store = m_service->ResolveTrustStoreHandle(ctx.client_id, ts_node.value());
    if (!trust_store.has_value())
    {
        return score::crypto::make_unexpected(trust_store.error());
    }

    const auto& fingerprint = fingerprint_res.value();
    const std::vector<std::uint8_t> owned_fingerprint{fingerprint.begin(), fingerprint.end()};
    const auto result =
        m_service->GetTrustStoreManager()->RemoveMember(trust_store.value(), owned_fingerprint, ctx.client_id);
    if (!result.has_value())
    {
        return score::crypto::make_unexpected(result.error());
    }
    return OkResponse();
}

// Parameter layout:
//   request[0] = trust-store node id (uint64)
//   request[1] = certificate node id (uint64); its fingerprint identifies the member to remove
Response TrustStoreManagementExecutor::HandleRemoveMemberById(const CertExecutionContext& ctx,
                                                              common::RequestParameters& request) const
{
    const auto ts_node = ExtractValue<std::uint64_t>(request, 0U);
    if (!ts_node.has_value())
    {
        return score::crypto::make_unexpected(ts_node.error());
    }
    const auto cert_node = ExtractValue<std::uint64_t>(request, 1U);
    if (!cert_node.has_value())
    {
        return score::crypto::make_unexpected(cert_node.error());
    }

    const auto trust_store = m_service->ResolveTrustStoreHandle(ctx.client_id, ts_node.value());
    if (!trust_store.has_value())
    {
        return score::crypto::make_unexpected(trust_store.error());
    }
    const auto cert = m_service->ResolveCertObject(ctx.client_id, cert_node.value());
    if (!cert.has_value())
    {
        return score::crypto::make_unexpected(cert.error());
    }

    const auto fingerprint = cert.value()->GetFingerprint();
    const std::vector<std::uint8_t> owned_fingerprint{fingerprint.begin(), fingerprint.end()};
    const auto result =
        m_service->GetTrustStoreManager()->RemoveMember(trust_store.value(), owned_fingerprint, ctx.client_id);
    if (!result.has_value())
    {
        return score::crypto::make_unexpected(result.error());
    }
    return OkResponse();
}

// Parameter layout:
//   request[0] = trust-store node id (uint64)
//   request[1] = member slot node id (uint64)
Response TrustStoreManagementExecutor::HandleEnableMember(const CertExecutionContext& ctx,
                                                          common::RequestParameters& request) const
{
    const auto ts_node = ExtractValue<std::uint64_t>(request, 0U);
    if (!ts_node.has_value())
    {
        return score::crypto::make_unexpected(ts_node.error());
    }
    const auto slot_node = ExtractValue<std::uint64_t>(request, 1U);
    if (!slot_node.has_value())
    {
        return score::crypto::make_unexpected(slot_node.error());
    }

    const auto trust_store = m_service->ResolveTrustStoreHandle(ctx.client_id, ts_node.value());
    if (!trust_store.has_value())
    {
        return score::crypto::make_unexpected(trust_store.error());
    }
    const auto slot = m_service->ResolveCertSlotHandle(ctx.client_id, slot_node.value());
    if (!slot.has_value())
    {
        return score::crypto::make_unexpected(slot.error());
    }

    const auto result =
        m_service->GetTrustStoreManager()->EnableMember(trust_store.value(), slot.value(), ctx.client_id);
    if (!result.has_value())
    {
        return score::crypto::make_unexpected(result.error());
    }
    return OkResponse();
}

// Parameter layout:
//   request[0] = trust-store node id (uint64)
//   request[1] = member slot node id (uint64)
Response TrustStoreManagementExecutor::HandleDisableMember(const CertExecutionContext& ctx,
                                                           common::RequestParameters& request) const
{
    const auto ts_node = ExtractValue<std::uint64_t>(request, 0U);
    if (!ts_node.has_value())
    {
        return score::crypto::make_unexpected(ts_node.error());
    }
    const auto slot_node = ExtractValue<std::uint64_t>(request, 1U);
    if (!slot_node.has_value())
    {
        return score::crypto::make_unexpected(slot_node.error());
    }

    const auto trust_store = m_service->ResolveTrustStoreHandle(ctx.client_id, ts_node.value());
    if (!trust_store.has_value())
    {
        return score::crypto::make_unexpected(trust_store.error());
    }
    const auto slot = m_service->ResolveCertSlotHandle(ctx.client_id, slot_node.value());
    if (!slot.has_value())
    {
        return score::crypto::make_unexpected(slot.error());
    }

    const auto result =
        m_service->GetTrustStoreManager()->DisableMember(trust_store.value(), slot.value(), ctx.client_id);
    if (!result.has_value())
    {
        return score::crypto::make_unexpected(result.error());
    }
    return OkResponse();
}

// Parameter layout:
//   request[0] = trust-store node id (uint64)
//   request[1] = member slot node id (uint64)
//   request[2] = SHA-256 fingerprint the caller accepts (32 bytes)
Response TrustStoreManagementExecutor::HandleAcknowledgeMemberUpdate(const CertExecutionContext& ctx,
                                                                     common::RequestParameters& request) const
{
    const auto ts_node = ExtractValue<std::uint64_t>(request, 0U);
    if (!ts_node.has_value())
    {
        return score::crypto::make_unexpected(ts_node.error());
    }
    const auto slot_node = ExtractValue<std::uint64_t>(request, 1U);
    if (!slot_node.has_value())
    {
        return score::crypto::make_unexpected(slot_node.error());
    }
    const auto accepted = ExtractFingerprint(request, 2U);
    if (!accepted.has_value())
    {
        return score::crypto::make_unexpected(accepted.error());
    }

    const auto trust_store = m_service->ResolveTrustStoreHandle(ctx.client_id, ts_node.value());
    if (!trust_store.has_value())
    {
        return score::crypto::make_unexpected(trust_store.error());
    }
    const auto slot = m_service->ResolveCertSlotHandle(ctx.client_id, slot_node.value());
    if (!slot.has_value())
    {
        return score::crypto::make_unexpected(slot.error());
    }

    const auto result = m_service->GetTrustStoreManager()->AcknowledgeMemberUpdate(
        trust_store.value(), slot.value(), accepted.value(), ctx.client_id);
    if (!result.has_value())
    {
        return score::crypto::make_unexpected(result.error());
    }
    return OkResponse();
}

// Parameter layout:
//   request[0] = trust-store node id (uint64)
//   request[1] = member slot node id (uint64)
//   request[2] = CRL encoding (uint8; kDer or kPem)
//   request[3] = encoded CRL (span<const uint8_t>)
// The CRL is validated against the certificate held in the member slot before it is stored.
Response TrustStoreManagementExecutor::HandleImportCrlForMember(const CertExecutionContext& ctx,
                                                                common::RequestParameters& request) const
{
    const auto ts_node = ExtractValue<std::uint64_t>(request, 0U);
    if (!ts_node.has_value())
    {
        return score::crypto::make_unexpected(ts_node.error());
    }
    const auto slot_node = ExtractValue<std::uint64_t>(request, 1U);
    if (!slot_node.has_value())
    {
        return score::crypto::make_unexpected(slot_node.error());
    }
    const auto format = ExtractValue<std::uint8_t>(request, 2U);
    if (!format.has_value())
    {
        return score::crypto::make_unexpected(format.error());
    }
    const auto crl_bytes = ExtractBytes(request, 3U);
    if (!crl_bytes.has_value())
    {
        return score::crypto::make_unexpected(crl_bytes.error());
    }

    const auto trust_store = m_service->ResolveTrustStoreHandle(ctx.client_id, ts_node.value());
    if (!trust_store.has_value())
    {
        return score::crypto::make_unexpected(trust_store.error());
    }
    const auto slot = m_service->ResolveCertSlotHandle(ctx.client_id, slot_node.value());
    if (!slot.has_value())
    {
        return score::crypto::make_unexpected(slot.error());
    }

    const auto issuer = m_service->GetSlotManager()->LoadCertificate(slot.value(), ctx.client_id);
    if (!issuer.has_value())
    {
        return score::crypto::make_unexpected(issuer.error());
    }

    auto crl = ValidateCrlAgainstIssuer(
        *m_cert_parser, *issuer.value(), crl_bytes.value(), static_cast<score::crypto::FormatType>(format.value()));
    if (!crl.has_value())
    {
        return score::crypto::make_unexpected(crl.error());
    }

    const auto result = m_service->GetTrustStoreManager()->StoreCrlForMember(
        trust_store.value(), slot.value(), crl.value(), ctx.client_id);
    if (!result.has_value())
    {
        return score::crypto::make_unexpected(result.error());
    }
    return OkResponse();
}

// Parameter layout:
//   request[0] = trust-store node id (uint64)
//   request[1] = member slot node id (uint64)
Response TrustStoreManagementExecutor::HandleDeleteCrlForMember(const CertExecutionContext& ctx,
                                                                common::RequestParameters& request) const
{
    const auto ts_node = ExtractValue<std::uint64_t>(request, 0U);
    if (!ts_node.has_value())
    {
        return score::crypto::make_unexpected(ts_node.error());
    }
    const auto slot_node = ExtractValue<std::uint64_t>(request, 1U);
    if (!slot_node.has_value())
    {
        return score::crypto::make_unexpected(slot_node.error());
    }

    const auto trust_store = m_service->ResolveTrustStoreHandle(ctx.client_id, ts_node.value());
    if (!trust_store.has_value())
    {
        return score::crypto::make_unexpected(trust_store.error());
    }
    const auto slot = m_service->ResolveCertSlotHandle(ctx.client_id, slot_node.value());
    if (!slot.has_value())
    {
        return score::crypto::make_unexpected(slot.error());
    }

    const auto result =
        m_service->GetTrustStoreManager()->ClearCrlForMember(trust_store.value(), slot.value(), ctx.client_id);
    if (!result.has_value())
    {
        return score::crypto::make_unexpected(result.error());
    }
    return OkResponse();
}

}  // namespace score::crypto::daemon::cert_management

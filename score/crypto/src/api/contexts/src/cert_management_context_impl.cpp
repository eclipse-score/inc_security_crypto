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

#include "score/crypto/src/api/contexts/src/cert_management_context_impl.hpp"

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/common/src/crypto_resource_guard_factory.hpp"
#include "score/crypto/src/api/common/src/i_release_callback.hpp"
#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"
#include "score/crypto/src/daemon/provider/cert_management/cert_management_operations.hpp"

#include "score/mw/log/logging.h"
#include "score/result/result.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace score
{

namespace crypto
{

namespace proto = ::score::crypto::daemon::control_plane::protocol;
namespace actors = ::score::crypto::daemon::common::actors;
namespace cm_ops = ::score::crypto::daemon::provider::cert_management;

// ===========================================================================
// ContextReleaseCallbackImpl — sends CTX_CLOSE on last reference drop
// ===========================================================================

class CertManagementContextImpl::ContextReleaseCallbackImpl final : public IReleaseCallback
{
  public:
    ContextReleaseCallbackImpl(std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
                               proto::DataNodeId context_id)
        : m_connection(std::move(connection)), m_context_id(context_id)
    {
    }

    ContextReleaseCallbackImpl(const ContextReleaseCallbackImpl&) = delete;
    ContextReleaseCallbackImpl& operator=(const ContextReleaseCallbackImpl&) = delete;
    ContextReleaseCallbackImpl(ContextReleaseCallbackImpl&&) = delete;
    ContextReleaseCallbackImpl& operator=(ContextReleaseCallbackImpl&&) = delete;

    ~ContextReleaseCallbackImpl() override
    {
        if (!m_connection)
        {
            score::mw::log::LogError() << "[API][CertMgmtCtxImpl] ERROR: Connection not initialized during CTX_CLOSE";
            return;
        }
        auto req = proto::ControlRequestBuilder()
                       .forDataNodeId(m_context_id)
                       .operation(score::crypto::daemon::mediator::operations::CloseContext())
                       .build();
        if (!req.has_value())
        {
            score::mw::log::LogError() << "[API][CertMgmtCtxImpl] ERROR: Failed to build CTX_CLOSE request";
            return;
        }
        auto resp = m_connection->SendRequest(req.value());
        auto validator = proto::ControlResponseValidator::FromResult(resp);
        validator.expectOperation(score::crypto::daemon::mediator::operations::CloseContext()).expectSuccess();
        if (!validator.isValid())
        {
            score::mw::log::LogError() << "[API][CertMgmtCtxImpl] ERROR: CTX_CLOSE failed: " << validator.getError();
        }
    }

    score::Result<std::monostate> ReleaseResource(const CryptoResourceId& /*id*/) noexcept override
    {
        return std::monostate{};
    }

  private:
    std::shared_ptr<score::crypto::api::control_plane::IConnection> m_connection;
    proto::DataNodeId m_context_id;
};

// ===========================================================================
// ReleaseCallbackImpl — sends CERT_RELEASE for guarded resources
// ===========================================================================

class CertManagementContextImpl::ReleaseCallbackImpl final : public IReleaseCallback
{
  public:
    ReleaseCallbackImpl(std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
                        proto::DataNodeId context_id,
                        std::shared_ptr<IReleaseCallback> context_release_callback)
        : m_connection(std::move(connection)),
          m_context_id(context_id),
          m_context_release_callback(std::move(context_release_callback))
    {
    }

    score::Result<std::monostate> ReleaseResource(const CryptoResourceId& id) noexcept override
    {
        const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_MANAGEMENT, cm_ops::CERT_RELEASE};
        auto req = proto::ControlRequestBuilder()
                       .forDataNodeId(m_context_id)
                       .operation(op_id)
                       .with_in_val_uint64(id.id)
                       .build();
        if (!req.has_value())
            return score::Result<std::monostate>{
                score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build CERT_RELEASE request")};

        auto resp = m_connection->SendRequest(req.value());
        auto validator = proto::ControlResponseValidator::FromResult(resp);
        validator.expectOperation(op_id).expectSuccess();
        if (!validator.isValid())
            return score::Result<std::monostate>{score::unexpect,
                                                 MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
        return std::monostate{};
    }

  private:
    std::shared_ptr<score::crypto::api::control_plane::IConnection> m_connection;
    proto::DataNodeId m_context_id;
    std::shared_ptr<IReleaseCallback> m_context_release_callback;
};

// ===========================================================================
// CertManagementContextImpl — construction / destruction
// ===========================================================================

CertManagementContextImpl::CertManagementContextImpl(
    std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
    uint64_t context_id)
    : m_connection(std::move(connection)),
      m_context_id(context_id),
      m_context_release_callback(std::make_shared<ContextReleaseCallbackImpl>(m_connection, m_context_id)),
      m_release_callback(std::make_shared<ReleaseCallbackImpl>(m_connection, m_context_id, m_context_release_callback))
{
}

CertManagementContextImpl::~CertManagementContextImpl() = default;

// ===========================================================================
// Parsing
// ===========================================================================

score::Result<CryptoResourceGuard> CertManagementContextImpl::ParseCertificate(
    score::cpp::span<const uint8_t> cert_data,
    FormatType format)
{
    // Request: [0]=format (uint8), [1]=cert bytes (data buffer)
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_MANAGEMENT, cm_ops::CERT_PARSE};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint8(static_cast<std::uint8_t>(format))
                   .with_in_data_buffer(cert_data)
                   .build();
    if (!req.has_value())
        return score::Result<CryptoResourceGuard>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build CERT_PARSE")};

    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<CryptoResourceGuard>{score::unexpect,
                                                  MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};

    // Response: [0][0]=uint64 node_id, [0][1]=uint16 provider_id
    auto nid_res = validator.getParameterAt<std::uint64_t>(0, 0);
    auto prov_res = validator.getParameterAt<std::uint16_t>(0, 1);
    if (!nid_res.has_value() || !prov_res.has_value())
        return score::Result<CryptoResourceGuard>{
            score::unexpect,
            MakeError(CryptoErrorCode::kOperationFailed, "CERT_PARSE response missing node_id/provider_id")};

    CryptoResourceId resource_id{};
    resource_id.id = nid_res.value();
    resource_id.type = ResourceType::kCertificate;
    resource_id.persistence = ResourcePersistence::kEphemeral;
    resource_id.primary_provider = prov_res.value();
    return CryptoResourceGuardFactory::Make(m_release_callback, resource_id);
}

score::Result<std::vector<CryptoResourceGuard>> CertManagementContextImpl::ParseCertificates(
    score::cpp::span<const uint8_t> cert_data,
    FormatType format)
{
    // Request: [0]=format (uint8), [1]=cert bytes (data buffer)
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_MANAGEMENT, cm_ops::CERT_PARSE_CHAIN};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint8(static_cast<std::uint8_t>(format))
                   .with_in_data_buffer(cert_data)
                   .build();
    if (!req.has_value())
        return score::Result<std::vector<CryptoResourceGuard>>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build CERT_PARSE_CHAIN")};

    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::vector<CryptoResourceGuard>>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};

    // Response: [0][0]=uint64 count, [0][1..N]=uint64 node_id per cert
    auto count_res = validator.getParameterAt<std::uint64_t>(0, 0);
    if (!count_res.has_value())
        return score::Result<std::vector<CryptoResourceGuard>>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "CERT_PARSE_CHAIN response missing count")};

    const std::size_t count = static_cast<std::size_t>(count_res.value());
    // CERT_PARSE_CHAIN returns certificate node IDs without provider affinity.
    constexpr std::uint16_t kNoProvider = 0U;

    std::vector<CryptoResourceGuard> result{};
    result.reserve(count);
    for (std::size_t i = 0U; i < count; ++i)
    {
        auto nid_res = validator.getParameterAt<std::uint64_t>(0, static_cast<int>(1U + i));
        if (!nid_res.has_value())
            return score::Result<std::vector<CryptoResourceGuard>>{
                score::unexpect,
                MakeError(CryptoErrorCode::kOperationFailed, "CERT_PARSE_CHAIN response missing node_id entry")};

        CryptoResourceId resource_id{};
        resource_id.id = nid_res.value();
        resource_id.type = ResourceType::kCertificate;
        resource_id.persistence = ResourcePersistence::kEphemeral;
        resource_id.primary_provider = kNoProvider;
        result.push_back(CryptoResourceGuardFactory::Make(m_release_callback, resource_id));
    }
    return result;
}

// ===========================================================================
// Persistence
// ===========================================================================

score::Result<std::monostate> CertManagementContextImpl::SaveCertificate(const CryptoResourceId& cert,
                                                                         const CryptoResourceId& target_slot)
{
    // Request: [0]=slot_node_id (uint64), [1]=cert_node_id (uint64)
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_MANAGEMENT, cm_ops::CERT_SAVE};
    auto builder = proto::ControlRequestBuilder()
                       .forDataNodeId(m_context_id)
                       .operation(op_id)
                       .with_in_val_uint64(target_slot.id)
                       .with_in_val_uint64(cert.id);
    auto req = std::move(builder).build();
    if (!req.has_value())
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, "Failed to build CERT_SAVE")};
    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    return std::monostate{};
}

score::Result<std::monostate> CertManagementContextImpl::SaveCertificateWithCrl(const CryptoResourceId& cert,
                                                                                const CryptoResourceId& target_slot)
{
    // Request: [0]=slot_node_id (uint64), [1]=cert_node_id (uint64), [2]=with_crl (uint8)
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_MANAGEMENT, cm_ops::CERT_SAVE};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint64(target_slot.id)
                   .with_in_val_uint64(cert.id)
                   .with_in_val_uint8(1U)
                   .build();
    if (!req.has_value())
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, "Failed to build CERT_SAVE")};
    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    return std::monostate{};
}

// ===========================================================================
// Export
// ===========================================================================

score::Result<std::size_t> CertManagementContextImpl::GetCertificateExportSize(const CryptoResourceId& cert,
                                                                               FormatType format)
{
    // Request: [0]=cert_node_id (uint64), [1]=format (uint8)
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_MANAGEMENT, cm_ops::CERT_GET_EXPORT_SIZE};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint64(cert.id)
                   .with_in_val_uint8(static_cast<std::uint8_t>(format))
                   .build();
    if (!req.has_value())
        return score::Result<std::size_t>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build CERT_GET_EXPORT_SIZE")};
    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::size_t>{score::unexpect,
                                          MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};

    auto size_res = validator.getParameterAt<std::uint64_t>(0, 0);
    if (!size_res.has_value())
        return score::Result<std::size_t>{
            score::unexpect,
            MakeError(CryptoErrorCode::kOperationFailed, "CERT_GET_EXPORT_SIZE response missing size")};
    return static_cast<std::size_t>(size_res.value());
}

score::Result<std::size_t> CertManagementContextImpl::ExportCertificate(const CryptoResourceId& cert,
                                                                        FormatType format,
                                                                        score::cpp::span<uint8_t> output)
{
    // Request: [0]=cert_node_id (uint64), [1]=format (uint8)
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_MANAGEMENT, cm_ops::CERT_EXPORT};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint64(cert.id)
                   .with_in_val_uint8(static_cast<std::uint8_t>(format))
                   .build();
    if (!req.has_value())
        return score::Result<std::size_t>{score::unexpect,
                                          MakeError(CryptoErrorCode::kOperationFailed, "Failed to build CERT_EXPORT")};
    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::size_t>{score::unexpect,
                                          MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};

    auto buf_res = validator.getParameterAt<daemon::common::OwnedBuffer>(0, 0);
    if (!buf_res.has_value())
        return score::Result<std::size_t>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "CERT_EXPORT response missing bytes")};

    const auto& buf = buf_res.value();
    if (static_cast<std::size_t>(output.size()) < buf.size())
        return score::Result<std::size_t>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "CERT_EXPORT output span too small")};

    std::copy(buf.begin(), buf.end(), output.data());
    return buf.size();
}

// ===========================================================================
// Format conversion
// ===========================================================================

score::Result<std::size_t> CertManagementContextImpl::GetConvertedCertificateSize(
    score::cpp::span<const uint8_t> /*input*/,
    FormatType /*input_format*/,
    FormatType /*output_format*/)
{
    return score::Result<std::size_t>{
        score::unexpect, MakeError(CryptoErrorCode::kUnsupportedOperation, "Format conversion is unavailable")};
}

score::Result<std::size_t> CertManagementContextImpl::ConvertCertificateFormat(
    score::cpp::span<const uint8_t> /*input*/,
    FormatType /*input_format*/,
    FormatType /*output_format*/,
    score::cpp::span<uint8_t> /*output*/)
{
    return score::Result<std::size_t>{
        score::unexpect, MakeError(CryptoErrorCode::kUnsupportedOperation, "Format conversion is unavailable")};
}

// ===========================================================================
// Slot management
// ===========================================================================

score::Result<std::monostate> CertManagementContextImpl::ClearCertificate(const CryptoResourceId& slot)
{
    // Request: [0]=slot_node_id (uint64)
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_MANAGEMENT, cm_ops::CERT_CLEAR};
    auto req =
        proto::ControlRequestBuilder().forDataNodeId(m_context_id).operation(op_id).with_in_val_uint64(slot.id).build();
    if (!req.has_value())
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build CERT_CLEAR")};
    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    return std::monostate{};
}

score::Result<CryptoResourceGuard> CertManagementContextImpl::LoadCertificate(const CryptoResourceId& slot)
{
    if (slot.type != ResourceType::kCertSlot)
        return score::Result<CryptoResourceGuard>{
            score::unexpect,
            MakeError(CryptoErrorCode::kInvalidArgument, "LoadCertificate requires a certificate slot")};

    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_MANAGEMENT, cm_ops::CERT_LOAD};
    auto req =
        proto::ControlRequestBuilder().forDataNodeId(m_context_id).operation(op_id).with_in_val_uint64(slot.id).build();
    if (!req.has_value())
        return score::Result<CryptoResourceGuard>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build CERT_LOAD")};

    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<CryptoResourceGuard>{score::unexpect,
                                                  MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};

    auto node_res = validator.getParameterAt<std::uint64_t>(0, 0);
    auto provider_res = validator.getParameterAt<std::uint16_t>(0, 1);
    if (!node_res.has_value() || !provider_res.has_value())
        return score::Result<CryptoResourceGuard>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "CERT_LOAD response incomplete")};

    CryptoResourceId resource_id{};
    resource_id.id = node_res.value();
    resource_id.type = ResourceType::kCertificate;
    resource_id.persistence = ResourcePersistence::kEphemeral;
    resource_id.primary_provider = provider_res.value();
    return CryptoResourceGuardFactory::Make(m_release_callback, resource_id);
}

// ===========================================================================
// Key extraction
// ===========================================================================

score::Result<std::pair<CryptoResourceGuard, AlgorithmId>> CertManagementContextImpl::LoadCertificatePublicKey(
    const CryptoResourceId& /*cert*/)
{
    return score::Result<std::pair<CryptoResourceGuard, AlgorithmId>>{
        score::unexpect,
        MakeError(CryptoErrorCode::kUnsupportedOperation, "Certificate public-key extraction is unavailable")};
}

// ===========================================================================
// CRL management
// ===========================================================================

score::Result<std::monostate> CertManagementContextImpl::ImportCrl(score::cpp::span<const uint8_t> crl_data,
                                                                   FormatType format,
                                                                   const CryptoResourceId& issuer_cert)
{
    // Request: [0]=certificate_node_id (uint64), [1]=format (uint8), [2]=CRL bytes
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_MANAGEMENT, cm_ops::CRL_IMPORT};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint64(issuer_cert.id)
                   .with_in_val_uint8(static_cast<std::uint8_t>(format))
                   .with_in_data_buffer(crl_data)
                   .build();
    if (!req.has_value())
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build CRL_IMPORT")};
    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    return std::monostate{};
}

score::Result<std::monostate> CertManagementContextImpl::ImportCrlToSlot(score::cpp::span<const uint8_t> crl_data,
                                                                         FormatType format,
                                                                         const CryptoResourceId& cert_slot)
{
    // Request: [0]=slot_node_id (uint64), [1]=format (uint8), [2]=CRL bytes
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_MANAGEMENT, cm_ops::CRL_IMPORT_TO_SLOT};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint64(cert_slot.id)
                   .with_in_val_uint8(static_cast<std::uint8_t>(format))
                   .with_in_data_buffer(crl_data)
                   .build();
    if (!req.has_value())
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build CRL_IMPORT_TO_SLOT")};
    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    return std::monostate{};
}

score::Result<std::monostate> CertManagementContextImpl::DeleteCrl(const CryptoResourceId& cert_slot)
{
    // Request: [0]=slot_node_id (uint64)
    const proto::OperationIdentifier op_id{actors::OP_ACTOR_CERT_MANAGEMENT, cm_ops::CRL_DELETE};
    auto req = proto::ControlRequestBuilder()
                   .forDataNodeId(m_context_id)
                   .operation(op_id)
                   .with_in_val_uint64(cert_slot.id)
                   .build();
    if (!req.has_value())
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kOperationFailed, "Failed to build CRL_DELETE")};
    auto resp = m_connection->SendRequest(req.value());
    auto validator = proto::ControlResponseValidator::FromResult(resp);
    validator.expectOperation(op_id).expectSuccess();
    if (!validator.isValid())
        return score::Result<std::monostate>{score::unexpect,
                                             MakeError(CryptoErrorCode::kOperationFailed, validator.getError())};
    return std::monostate{};
}

}  // namespace crypto

}  // namespace score

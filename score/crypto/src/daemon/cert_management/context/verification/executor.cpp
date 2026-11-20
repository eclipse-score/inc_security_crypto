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

#include "score/crypto/src/daemon/cert_management/context/verification/executor.hpp"

#include "score/crypto/src/daemon/cert_management/interfaces/cert_verification_operations.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/crl_metadata_wire_layout.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/mw/log/logging.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace score::crypto::daemon::cert_management
{

namespace
{

constexpr std::string_view kLogPrefix{"[CERT_VERIFY_EXEC] "};
namespace cv_ops = ::score::crypto::daemon::cert_management::operations;
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

/// Extract every parameter as a data-node identifier; each parameter must be a uint64.
score::crypto::Expected<std::vector<data_manager::DataNodeId>, Error> ExtractNodeIds(
    const common::RequestParameters& request)
{
    std::vector<data_manager::DataNodeId> node_ids;
    node_ids.reserve(request.size());
    for (std::size_t index = 0U; index < request.size(); ++index)
    {
        auto node_id = ExtractValue<std::uint64_t>(request, index);
        if (!node_id.has_value())
        {
            return score::crypto::make_unexpected(node_id.error());
        }
        node_ids.push_back(node_id.value());
    }
    return node_ids;
}

/// Copy @p bytes into the output buffer at @p index; fails when the buffer is absent or cannot hold them.
score::crypto::Expected<std::monostate, Error> CopyToOutput(common::RequestParameters& request,
                                                            std::size_t index,
                                                            const std::vector<std::uint8_t>& bytes)
{
    if (request.size() <= index)
    {
        return score::crypto::make_unexpected(Error::kInsufficientParameters);
    }
    auto* output = std::get_if<score::crypto::span<std::uint8_t>>(&request[index]);
    if (output == nullptr || output->size() < bytes.size() || (!bytes.empty() && output->data() == nullptr))
    {
        return score::crypto::make_unexpected(Error::kInsufficientBufferSize);
    }
    std::copy(bytes.begin(), bytes.end(), output->begin());
    return std::monostate{};
}

common::ResponseParameters OkResponse()
{
    common::ResponseParameters out;
    out.push_back(static_cast<std::uint64_t>(0U));
    return out;
}

/// Map the result of a setter that returns no value to the wire acknowledgement.
Response Acknowledge(const score::crypto::Expected<std::monostate, Error>& result)
{
    if (!result.has_value())
    {
        return score::crypto::make_unexpected(result.error());
    }
    return OkResponse();
}

}  // namespace

score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> CertVerificationExecutor::Execute(
    CertVerificationSession& session,
    const common::OperationIdentifier& operation_id,
    common::RequestParameters& request) const
{
    if (operation_id.operationActor != common::actors::OP_ACTOR_CERT_VERIFICATION)
    {
        score::mw::log::LogError() << kLogPrefix
                                   << "Operation issued with an actor other than certificate verification";
        return score::crypto::make_unexpected(Error::kUnsupportedOperation);
    }

    const auto action = operation_id.operationAction;

    if (action == cv_ops::CERT_VERIFY_SET_LEAF)
    {
        return HandleSetLeaf(session, request);
    }
    if (action == cv_ops::CERT_VERIFY_SET_CHAIN)
    {
        return HandleSetChain(session, request);
    }
    if (action == cv_ops::CERT_VERIFY_SET_TRUST_STORE)
    {
        return HandleSetTrustStore(session, request);
    }
    if (action == cv_ops::CERT_VERIFY_SET_TRUSTED)
    {
        return HandleSetTrusted(session, request);
    }
    if (action == cv_ops::CERT_VERIFY_SET_POLICY)
    {
        return HandleSetChainTerminationPolicy(session, request);
    }
    if (action == cv_ops::CERT_VERIFY_SET_UNTRUSTED)
    {
        return HandleSetUntrusted(session, request);
    }
    if (action == cv_ops::CERT_VERIFY_SET_VERIFICATION_TIME)
    {
        return HandleSetVerificationTime(session, request);
    }
    if (action == cv_ops::CERT_VERIFY_SET_REVOCATION_POLICY)
    {
        return HandleSetRevocationCheckPolicy(session, request);
    }
    if (action == cv_ops::CERT_VERIFY_SET_REVOCATION_COVERAGE_POLICY)
    {
        return HandleSetRevocationCoveragePolicy(session, request);
    }
    if (action == cv_ops::CERT_VERIFY_SET_EVIDENCE_MODE)
    {
        return HandleSetEvidenceMode(session, request);
    }
    if (action == cv_ops::CERT_VERIFY)
    {
        return HandleVerify(session);
    }
    if (action == cv_ops::CERT_GET_VERIFIED_CHAIN_EXPORT_SIZE)
    {
        return HandleGetVerifiedChainExportSize(session, request);
    }
    if (action == cv_ops::CERT_EXPORT_VERIFIED_CHAIN)
    {
        return HandleExportVerifiedChain(session, request);
    }
    if (action == cv_ops::CERT_GET_VERIFIED_CERT_EXPORT_SIZE)
    {
        return HandleGetVerifiedCertificateExportSize(session, request);
    }
    if (action == cv_ops::CERT_EXPORT_VERIFIED_CERT)
    {
        return HandleExportVerifiedCertificate(session, request);
    }
    if (action == cv_ops::CERT_GET_SELECTED_CRL_METADATA)
    {
        return HandleGetSelectedCrlMetadata(session, request);
    }

    score::mw::log::LogError() << kLogPrefix << "Unknown action 0x" << score::mw::log::LogHex16{action};
    return score::crypto::make_unexpected(Error::kUnsupportedOperation);
}

// Parameter layout:
//   request[0] = certificate node id (uint64)
// Response: acknowledgement (uint64 0)
Response CertVerificationExecutor::HandleSetLeaf(CertVerificationSession& session,
                                                 const common::RequestParameters& request)
{
    const auto node_id = ExtractValue<std::uint64_t>(request, 0U);
    if (!node_id.has_value())
    {
        return score::crypto::make_unexpected(node_id.error());
    }
    return Acknowledge(session.SetLeaf(node_id.value()));
}

// Parameter layout:
//   request[i] = certificate node id (uint64), leaf first, for every parameter
// Response: acknowledgement (uint64 0)
Response CertVerificationExecutor::HandleSetChain(CertVerificationSession& session,
                                                  const common::RequestParameters& request)
{
    const auto node_ids = ExtractNodeIds(request);
    if (!node_ids.has_value())
    {
        return score::crypto::make_unexpected(node_ids.error());
    }
    return Acknowledge(session.SetChain(node_ids.value()));
}

// Parameter layout:
//   request[0] = trust store node id (uint64)
// Response: acknowledgement (uint64 0)
Response CertVerificationExecutor::HandleSetTrustStore(CertVerificationSession& session,
                                                       const common::RequestParameters& request)
{
    const auto node_id = ExtractValue<std::uint64_t>(request, 0U);
    if (!node_id.has_value())
    {
        return score::crypto::make_unexpected(node_id.error());
    }
    return Acknowledge(session.SetTrustStore(node_id.value()));
}

// Parameter layout:
//   request[i] = certificate node id (uint64), for every parameter; an empty list clears the explicit anchors
// Response: acknowledgement (uint64 0)
Response CertVerificationExecutor::HandleSetTrusted(CertVerificationSession& session,
                                                    const common::RequestParameters& request)
{
    const auto node_ids = ExtractNodeIds(request);
    if (!node_ids.has_value())
    {
        return score::crypto::make_unexpected(node_ids.error());
    }
    return Acknowledge(session.SetTrusted(node_ids.value()));
}

// Parameter layout:
//   request[0] = ChainTerminationPolicy (uint8)
// Response: acknowledgement (uint64 0)
Response CertVerificationExecutor::HandleSetChainTerminationPolicy(CertVerificationSession& session,
                                                                   const common::RequestParameters& request)
{
    const auto policy = ExtractValue<std::uint8_t>(request, 0U);
    if (!policy.has_value())
    {
        return score::crypto::make_unexpected(policy.error());
    }
    if (policy.value() > static_cast<std::uint8_t>(score::crypto::ChainTerminationPolicy::kTrustStoreTerminated))
    {
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }
    session.SetChainTerminationPolicy(static_cast<score::crypto::ChainTerminationPolicy>(policy.value()));
    return OkResponse();
}

// Parameter layout:
//   request[i] = certificate node id (uint64), for every parameter; an empty list clears the untrusted set
// Response: acknowledgement (uint64 0)
Response CertVerificationExecutor::HandleSetUntrusted(CertVerificationSession& session,
                                                      const common::RequestParameters& request)
{
    const auto node_ids = ExtractNodeIds(request);
    if (!node_ids.has_value())
    {
        return score::crypto::make_unexpected(node_ids.error());
    }
    return Acknowledge(session.SetUntrusted(node_ids.value()));
}

// Parameter layout:
//   request[0] = verification time, epoch seconds carried as the bit pattern of a uint64
// Response: acknowledgement (uint64 0)
Response CertVerificationExecutor::HandleSetVerificationTime(CertVerificationSession& session,
                                                             const common::RequestParameters& request)
{
    const auto epoch_s = ExtractValue<std::uint64_t>(request, 0U);
    if (!epoch_s.has_value())
    {
        return score::crypto::make_unexpected(epoch_s.error());
    }
    session.SetVerificationTime(static_cast<std::int64_t>(epoch_s.value()));
    return OkResponse();
}

// Parameter layout:
//   request[0] = RevocationCheckPolicy (uint8)
// Response: acknowledgement (uint64 0)
Response CertVerificationExecutor::HandleSetRevocationCheckPolicy(CertVerificationSession& session,
                                                                  const common::RequestParameters& request)
{
    const auto policy = ExtractValue<std::uint8_t>(request, 0U);
    if (!policy.has_value())
    {
        return score::crypto::make_unexpected(policy.error());
    }
    if (policy.value() > static_cast<std::uint8_t>(score::crypto::RevocationCheckPolicy::kOcspWithCrlFallback))
    {
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }
    session.SetRevocationCheckPolicy(static_cast<score::crypto::RevocationCheckPolicy>(policy.value()));
    return OkResponse();
}

// Parameter layout:
//   request[0] = RevocationCoveragePolicy (uint8)
// Response: acknowledgement (uint64 0)
Response CertVerificationExecutor::HandleSetRevocationCoveragePolicy(CertVerificationSession& session,
                                                                     const common::RequestParameters& request)
{
    const auto policy = ExtractValue<std::uint8_t>(request, 0U);
    if (!policy.has_value())
    {
        return score::crypto::make_unexpected(policy.error());
    }
    if (policy.value() > static_cast<std::uint8_t>(score::crypto::RevocationCoveragePolicy::kBestEffort))
    {
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }
    session.SetRevocationCoveragePolicy(static_cast<score::crypto::RevocationCoveragePolicy>(policy.value()));
    return OkResponse();
}

// Parameter layout:
//   request[0] = VerificationEvidenceMode (uint8)
// Response: acknowledgement (uint64 0)
Response CertVerificationExecutor::HandleSetEvidenceMode(CertVerificationSession& session,
                                                         const common::RequestParameters& request)
{
    const auto mode = ExtractValue<std::uint8_t>(request, 0U);
    if (!mode.has_value())
    {
        return score::crypto::make_unexpected(mode.error());
    }
    if (mode.value() > static_cast<std::uint8_t>(score::crypto::VerificationEvidenceMode::kChainAndCrl))
    {
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }
    session.SetEvidenceMode(static_cast<score::crypto::VerificationEvidenceMode>(mode.value()));
    return OkResponse();
}

// Parameter layout: none
// Response: request[0] = CertVerifyResult (uint8), response[1] = verified chain certificate count (uint32)
Response CertVerificationExecutor::HandleVerify(CertVerificationSession& session)
{
    auto verdict = session.Verify();
    if (!verdict.has_value())
    {
        return score::crypto::make_unexpected(verdict.error());
    }
    common::ResponseParameters out;
    out.push_back(static_cast<std::uint8_t>(verdict.value()));
    out.push_back(static_cast<std::uint32_t>(session.GetVerifiedChainCertificateCount()));
    return out;
}

// Parameter layout:
//   request[0] = output format (uint8)
// Response: encoded chain size (uint64)
Response CertVerificationExecutor::HandleGetVerifiedChainExportSize(CertVerificationSession& session,
                                                                    const common::RequestParameters& request)
{
    const auto format = ExtractValue<std::uint8_t>(request, 0U);
    if (!format.has_value())
    {
        return score::crypto::make_unexpected(format.error());
    }
    auto encoded = session.ExportVerifiedChain(static_cast<score::crypto::FormatType>(format.value()));
    if (!encoded.has_value())
    {
        return score::crypto::make_unexpected(encoded.error());
    }
    common::ResponseParameters out;
    out.push_back(static_cast<std::uint64_t>(encoded.value().size()));
    return out;
}

// Parameter layout:
//   request[0] = output format (uint8)
//   request[1] = output buffer (span<uint8_t>)
// Response: encoded chain size (uint64)
Response CertVerificationExecutor::HandleExportVerifiedChain(CertVerificationSession& session,
                                                             common::RequestParameters& request)
{
    if (request.size() < 2U)
    {
        return score::crypto::make_unexpected(Error::kInsufficientParameters);
    }
    const auto format = ExtractValue<std::uint8_t>(request, 0U);
    if (!format.has_value())
    {
        return score::crypto::make_unexpected(format.error());
    }
    auto encoded = session.ExportVerifiedChain(static_cast<score::crypto::FormatType>(format.value()));
    if (!encoded.has_value())
    {
        return score::crypto::make_unexpected(encoded.error());
    }
    const auto copied = CopyToOutput(request, 1U, encoded.value());
    if (!copied.has_value())
    {
        return score::crypto::make_unexpected(copied.error());
    }
    common::ResponseParameters out;
    out.push_back(static_cast<std::uint64_t>(encoded.value().size()));
    return out;
}

// Parameter layout:
//   request[0] = certificate index in the verified chain (uint64)
//   request[1] = output format (uint8)
// Response: encoded certificate size (uint64)
Response CertVerificationExecutor::HandleGetVerifiedCertificateExportSize(CertVerificationSession& session,
                                                                          const common::RequestParameters& request)
{
    const auto index = ExtractValue<std::uint64_t>(request, 0U);
    if (!index.has_value())
    {
        return score::crypto::make_unexpected(index.error());
    }
    const auto format = ExtractValue<std::uint8_t>(request, 1U);
    if (!format.has_value())
    {
        return score::crypto::make_unexpected(format.error());
    }
    auto encoded = session.ExportVerifiedCertificate(static_cast<std::size_t>(index.value()),
                                                     static_cast<score::crypto::FormatType>(format.value()));
    if (!encoded.has_value())
    {
        return score::crypto::make_unexpected(encoded.error());
    }
    common::ResponseParameters out;
    out.push_back(static_cast<std::uint64_t>(encoded.value().size()));
    return out;
}

// Parameter layout:
//   request[0] = certificate index in the verified chain (uint64)
//   request[1] = output format (uint8)
//   request[2] = output buffer (span<uint8_t>)
// Response: encoded certificate size (uint64)
Response CertVerificationExecutor::HandleExportVerifiedCertificate(CertVerificationSession& session,
                                                                   common::RequestParameters& request)
{
    if (request.size() < 3U)
    {
        return score::crypto::make_unexpected(Error::kInsufficientParameters);
    }
    const auto index = ExtractValue<std::uint64_t>(request, 0U);
    if (!index.has_value())
    {
        return score::crypto::make_unexpected(index.error());
    }
    const auto format = ExtractValue<std::uint8_t>(request, 1U);
    if (!format.has_value())
    {
        return score::crypto::make_unexpected(format.error());
    }
    auto encoded = session.ExportVerifiedCertificate(static_cast<std::size_t>(index.value()),
                                                     static_cast<score::crypto::FormatType>(format.value()));
    if (!encoded.has_value())
    {
        return score::crypto::make_unexpected(encoded.error());
    }
    const auto copied = CopyToOutput(request, 2U, encoded.value());
    if (!copied.has_value())
    {
        return score::crypto::make_unexpected(copied.error());
    }
    common::ResponseParameters out;
    out.push_back(static_cast<std::uint64_t>(encoded.value().size()));
    return out;
}

// Parameter layout:
//   none: count-only query
//   request[0] = output buffer (span<uint8_t>): the packed entries are written here
// Response: entry count (uint64); with an output buffer also the number of bytes written (uint64)
// The packed entries are bulk data and are returned through the output buffer only. Each entry is
// CrlMetadataWireLayout::kEntrySize bytes.
Response CertVerificationExecutor::HandleGetSelectedCrlMetadata(CertVerificationSession& session,
                                                                common::RequestParameters& request)
{
    auto packed = session.GetSelectedCrlMetadata();
    if (!packed.has_value())
    {
        return score::crypto::make_unexpected(packed.error());
    }
    const auto entry_count = static_cast<std::uint64_t>(packed.value().size() / CrlMetadataWireLayout::kEntrySize);

    common::ResponseParameters out;
    if (request.empty())
    {
        out.push_back(entry_count);
        return out;
    }
    const auto copied = CopyToOutput(request, 0U, packed.value());
    if (!copied.has_value())
    {
        return score::crypto::make_unexpected(copied.error());
    }
    out.push_back(entry_count);
    out.push_back(static_cast<std::uint64_t>(packed.value().size()));
    return out;
}

}  // namespace score::crypto::daemon::cert_management

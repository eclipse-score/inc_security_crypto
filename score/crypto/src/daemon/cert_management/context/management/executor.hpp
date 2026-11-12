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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CONTEXT_MANAGEMENT_EXECUTOR_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CONTEXT_MANAGEMENT_EXECUTOR_HPP

#include "score/crypto/src/daemon/cert_management/context/cert_execution_context.hpp"
#include "score/crypto/src/daemon/cert_management/core/cert_management_service.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/cert_management/i_cert_parser.hpp"

#include <cstdint>
#include <vector>

namespace score::crypto::daemon::cert_management
{

/// @brief Executes CERT:MANAGEMENT operations against the certificate management service.
///
/// Each operation resolves the caller's data nodes through the service, performs the work, and returns the wire
/// response. Operations owned by other context types (public-key loading, OCSP) are refused with
/// kUnsupportedOperation.
///
/// The executor holds no mutable state. Execute() may be called concurrently; the synchronization of the
/// operations it reaches is documented on CertManagementService.
class CertManagementExecutor final
{
  public:
    /// @brief Construct the executor.
    /// @param cert_parser Parser used for certificate parsing, encoding, and CRL validation. Must be non-null.
    /// @param service Certificate management service that owns the data nodes and slots. Must be non-null.
    CertManagementExecutor(provider::cert_management::ICertParser::Sptr cert_parser,
                           CertManagementService::Sptr service);

    /// @brief Execute one CERT:MANAGEMENT operation.
    /// @param ctx Caller identity and context node for the operation.
    /// @param operation_id Actor and action codes of the operation.
    /// @param request Operation parameters, in the layout documented per operation in the implementation.
    /// @return The response parameters, or the error code of the failed step.
    [[nodiscard]] score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> Execute(
        const CertExecutionContext& ctx,
        const common::OperationIdentifier& operation_id,
        common::RequestParameters& request) const;

  private:
    [[nodiscard]] score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> HandleParse(
        const CertExecutionContext& ctx,
        common::RequestParameters& request) const;

    [[nodiscard]] score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> HandleParseChain(
        const CertExecutionContext& ctx,
        common::RequestParameters& request) const;

    [[nodiscard]] score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> HandleLoad(
        const CertExecutionContext& ctx,
        common::RequestParameters& request) const;

    [[nodiscard]] score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> HandleSave(
        const CertExecutionContext& ctx,
        common::RequestParameters& request) const;

    [[nodiscard]] score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> HandleExport(
        const CertExecutionContext& ctx,
        common::RequestParameters& request) const;

    [[nodiscard]] score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> HandleGetExportSize(
        const CertExecutionContext& ctx,
        common::RequestParameters& request) const;

    [[nodiscard]] score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> HandleClear(
        const CertExecutionContext& ctx,
        common::RequestParameters& request) const;

    [[nodiscard]] score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> HandleRelease(
        const CertExecutionContext& ctx,
        common::RequestParameters& request) const;

    [[nodiscard]] score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode>
    HandleCrlImportToCertificate(const CertExecutionContext& ctx, common::RequestParameters& request) const;

    [[nodiscard]] score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> HandleCrlImportToSlot(
        const CertExecutionContext& ctx,
        common::RequestParameters& request) const;

    /// CRL import parameters decoded from request[0..2]; both import scopes share this layout.
    struct CrlImportParams
    {
        std::uint64_t node_id;                              ///< Target node: certificate or slot, by scope.
        score::crypto::FormatType format;                   ///< Encoding of the CRL bytes.
        score::crypto::span<const std::uint8_t> crl_bytes;  ///< CRL bytes, borrowed from the request.
    };

    [[nodiscard]] static score::crypto::Expected<CrlImportParams, common::DaemonErrorCode> ParseCrlImportParams(
        common::RequestParameters& request);

    [[nodiscard]] score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> HandleCrlDelete(
        const CertExecutionContext& ctx,
        common::RequestParameters& request) const;

    [[nodiscard]] score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> HandleConvert(
        const CertExecutionContext& ctx,
        common::RequestParameters& request) const;

    [[nodiscard]] score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> HandleGetConvertSize(
        const CertExecutionContext& ctx,
        common::RequestParameters& request) const;

    /// Parse the certificate in request[2] from the format in request[0] and encode it in the format in request[1].
    [[nodiscard]] score::crypto::Expected<std::vector<std::uint8_t>, common::DaemonErrorCode> ConvertCertificateBytes(
        const common::RequestParameters& request) const;

    /// Resolve the certificate in request[0] and encode it in the format in request[1].
    [[nodiscard]] score::crypto::Expected<std::vector<std::uint8_t>, common::DaemonErrorCode> EncodeCertificateNode(
        const CertExecutionContext& ctx,
        const common::RequestParameters& request) const;

    provider::cert_management::ICertParser::Sptr m_cert_parser;
    CertManagementService::Sptr m_service;
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CONTEXT_MANAGEMENT_EXECUTOR_HPP

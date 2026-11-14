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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_QUERY_GET_CERTIFICATE_PUBLIC_KEY_QUERY_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_QUERY_GET_CERTIFICATE_PUBLIC_KEY_QUERY_HPP

#include "score/crypto/src/daemon/cert_management/core/cert_management_service.hpp"
#include "score/crypto/src/daemon/common/context/i_mediator_query.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"

namespace score::crypto::daemon::cert_management::query
{

/// @brief Serves GET_CERTIFICATE_PUBLIC_KEY: writes the SubjectPublicKeyInfo of a certificate into the caller's buffer.
///
/// The request names the certificate by node id and carries the SHA-256 fingerprint the caller read from its snapshot.
/// The query refuses the request when the node no longer holds that certificate, so the key returned always belongs to
/// the certificate the snapshot describes.
///
/// Registered with the mediator under operations::GET_CERTIFICATE_PUBLIC_KEY.
class GetCertificatePublicKeyQuery final : public common::IMediatorQuery
{
  public:
    /// @brief Create the query.
    /// @param service Certificate-management service that resolves data nodes. Must not be null.
    explicit GetCertificatePublicKeyQuery(CertManagementService::Sptr service) noexcept;

    /// @brief Write the public key of the certificate in the request to the caller's buffer.
    /// @return True if the key was written.
    [[nodiscard]] bool Handle(const control_plane::protocol::ControlRequest& request,
                              const control_plane::protocol::SingleOperationRequest& operation,
                              control_plane::protocol::OperationResponseBuilder& responseBuilder) override;

  private:
    CertManagementService::Sptr m_service;
};

}  // namespace score::crypto::daemon::cert_management::query

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_QUERY_GET_CERTIFICATE_PUBLIC_KEY_QUERY_HPP

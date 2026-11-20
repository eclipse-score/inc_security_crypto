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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_QUERY_GET_TRUST_STORE_MEMBER_ID_LIST_QUERY_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_QUERY_GET_TRUST_STORE_MEMBER_ID_LIST_QUERY_HPP

#include "score/crypto/src/daemon/cert_management/core/cert_management_service.hpp"
#include "score/crypto/src/daemon/common/context/i_mediator_query.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"

namespace score::crypto::daemon::cert_management::query
{

/// @brief Serves GET_TRUST_STORE_MEMBER_ID_LIST: returns the client-scoped node identifiers of a trust store's
///        occupied members.
///
/// Registered with the mediator under operations::GET_TRUST_STORE_MEMBER_ID_LIST. This is the first of the two calls
/// that read a trust store. The response layout is defined by BuildTrustStoreMemberIdListResponse.
class GetTrustStoreMemberIdListQuery final : public common::IMediatorQuery
{
  public:
    /// @brief Create the query.
    /// @param service Certificate-management service that resolves trust stores and data nodes. Must not be null.
    explicit GetTrustStoreMemberIdListQuery(CertManagementService::Sptr service) noexcept;

    /// @brief Resolve the trust-store node in the request and write the occupied member identifiers to the response.
    /// @return True if the identifiers were written.
    [[nodiscard]] bool Handle(const control_plane::protocol::ControlRequest& request,
                              const control_plane::protocol::SingleOperationRequest& operation,
                              control_plane::protocol::OperationResponseBuilder& responseBuilder) override;

  private:
    CertManagementService::Sptr m_service;
};

}  // namespace score::crypto::daemon::cert_management::query

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_QUERY_GET_TRUST_STORE_MEMBER_ID_LIST_QUERY_HPP

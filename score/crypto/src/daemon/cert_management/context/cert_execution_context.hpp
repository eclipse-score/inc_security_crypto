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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CONTEXT_CERT_EXECUTION_CONTEXT_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CONTEXT_CERT_EXECUTION_CONTEXT_HPP

#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/data_manager/data_node.hpp"

namespace score::crypto::daemon::cert_management
{

/// @brief Caller identity and context node for one operation of a certificate context.
struct CertExecutionContext final
{
    /// Provider identifier reported in parse and load responses.
    common::ProviderId provider_id{common::kInvalidProviderId};
    /// Authenticated client that issued the operation.
    data_manager::ClientId client_id{0U};
    /// Context node that parents the certificate data nodes created by the operation.
    data_manager::DataNodeId context_node_id{0U};
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CONTEXT_CERT_EXECUTION_CONTEXT_HPP

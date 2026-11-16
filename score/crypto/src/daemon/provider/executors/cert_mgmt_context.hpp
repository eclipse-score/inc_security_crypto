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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_EXECUTORS_CERT_MGMT_CONTEXT_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_EXECUTORS_CERT_MGMT_CONTEXT_HPP

#include "score/crypto/src/daemon/common/types.hpp"

#include <cstdint>

namespace score::crypto::daemon::provider::crypto_executor
{

/// Per-request context for cert_management-domain executor operations.
///
/// Shared by CertManagementExecutor (CERT:MANAGEMENT) and
/// TrustStoreManagementExecutor (CERT:TRUST_STORE) — both dispatch different
/// operation sets against the same client/provider/context identity shape, so
/// one struct serves both rather than duplicating an identical POD per executor.
///
/// Set once during InitializeContext() and remains constant for the
/// lifetime of the handler context.
struct CertMgmtExecutionContext
{
    common::ProviderId provider_id{common::kInvalidProviderId};
    std::uint64_t client_id{0U};
    std::uint64_t context_node_id{0U};
};

}  // namespace score::crypto::daemon::provider::crypto_executor

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_EXECUTORS_CERT_MGMT_CONTEXT_HPP

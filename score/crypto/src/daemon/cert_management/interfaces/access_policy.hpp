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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_INTERFACES_ACCESS_POLICY_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_INTERFACES_ACCESS_POLICY_HPP

#include <cstdint>
#include <vector>

namespace score::crypto::daemon::cert_management
{

/// UID-based read/write access control policy for a certificate slot or trust store.
struct AccessPolicy
{
    /// Reserved for future UID-based read authorization. Certificate reads are
    /// currently allowed after DataManager node ownership is established.
    std::vector<uint32_t> allowed_uids;

    /// UIDs permitted to write to this slot (SaveCertificate, CRL_IMPORT,
    /// CERT_CLEAR, TRUST_STORE_ADD_CERT, TRUST_STORE_REMOVE_CERT).
    ///
    /// Mutation authorization is explicit and default-deny: an empty list
    /// grants no write permission. Trust-store-owned exclusive slots do not
    /// use this list; their writes are authorized by TrustStoreManager.
    std::vector<uint32_t> allowed_write_uids;
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_INTERFACES_ACCESS_POLICY_HPP

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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_CERT_VERIFICATION_DETAIL_OPENSSL_REVOCATION_COVERAGE_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_CERT_VERIFICATION_DETAIL_OPENSSL_REVOCATION_COVERAGE_HPP

#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/cert_verification/detail/openssl_crl_selection.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/cert_verification/detail/openssl_x509_utils.hpp"

#include <openssl/x509.h>

#include <cstdint>
#include <vector>

namespace score::crypto::daemon::provider::openssl::detail
{

/// Per-verification state read by VerifyCrlCoverageCallback via X509_STORE_CTX app data.
struct RevocationCoverageState
{
    bool best_effort{false};
};

/// @brief X509_STORE_CTX verify callback implementing the revocation coverage policy.
///
/// Passes through checks that succeeded. For a failed check, it clears the error and continues only when
/// the failure is missing or unusable CRL evidence and RevocationCoverageState::best_effort is set in the
/// context's app data; otherwise the failure is kept.
///
/// @param ok Result of the current check (1 = passed).
/// @param ctx Verification context; its app data must be a RevocationCoverageState or null.
/// @return 1 to continue verification, 0 to fail it.
int VerifyCrlCoverageCallback(int ok, X509_STORE_CTX* ctx);

/// @brief Detects a certificate on the verified path that is listed only by a stale CRL.
///
/// A CRL is stale when @p verification_time is outside its thisUpdate/nextUpdate window or either time is
/// missing. Only CRLs whose signature verifies against a matching issuer candidate are considered. Such a
/// listing is indeterminate rather than proof of revocation, since a later CRL may have changed the status.
///
/// @param selected CRLs returned by SelectCrlsPerIssuer().
/// @param issuer_candidates Certificates that may have signed the CRLs.
/// @param verified_path Certificate path from the verification context; may be null.
/// @param verification_time Verification time in seconds since the Unix epoch.
/// @return True if a stale, validly signed CRL lists a certificate in @p verified_path.
[[nodiscard]] bool HasStaleRevocationEntry(const std::vector<ParsedCrl>& selected,
                                           const std::vector<CertSptr>& issuer_candidates,
                                           STACK_OF(X509) * verified_path,
                                           std::int64_t verification_time);

}  // namespace score::crypto::daemon::provider::openssl::detail

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_CERT_VERIFICATION_DETAIL_OPENSSL_REVOCATION_COVERAGE_HPP

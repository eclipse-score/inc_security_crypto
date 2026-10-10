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

#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/cert_verification/detail/openssl_revocation_coverage.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <memory>

namespace score::crypto::daemon::provider::openssl::detail
{

namespace
{

bool IsUnavailableCrlError(int x509_err)
{
    switch (x509_err)
    {
        case X509_V_ERR_UNABLE_TO_GET_CRL:
        case X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER:
        case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
        case X509_V_ERR_CRL_SIGNATURE_FAILURE:
        case X509_V_ERR_CRL_NOT_YET_VALID:
        case X509_V_ERR_CRL_HAS_EXPIRED:
            return true;
        default:
            return false;
    }
}

}  // namespace

int VerifyCrlCoverageCallback(int ok, X509_STORE_CTX* ctx)
{
    if (ok == 1)
        return 1;

    auto* state = static_cast<RevocationCoverageState*>(X509_STORE_CTX_get_app_data(ctx));
    if (state == nullptr || !state->best_effort || !IsUnavailableCrlError(X509_STORE_CTX_get_error(ctx)))
        return 0;

    X509_STORE_CTX_set_error(ctx, X509_V_OK);
    return 1;
}

bool HasStaleRevocationEntry(const std::vector<ParsedCrl>& selected,
                             const std::vector<CertSptr>& issuer_candidates,
                             STACK_OF(X509) * verified_path,
                             std::int64_t verification_time)
{
    if (verified_path == nullptr)
        return false;

    for (const auto& candidate : selected)
    {
        const auto& times = candidate.metadata;
        const bool fresh = times.this_update != 0 && times.this_update <= verification_time && times.next_update != 0 &&
                           times.next_update >= verification_time;
        if (fresh)
            continue;

        bool signature_valid = false;
        for (const auto& issuer_candidate : issuer_candidates)
        {
            if (!issuer_candidate)
                continue;
            auto issuer = CertToX509(*issuer_candidate);
            if (!issuer ||
                X509_NAME_cmp(X509_CRL_get_issuer(candidate.value.get()), X509_get_subject_name(issuer.get())) != 0)
                continue;

            std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> issuer_key{X509_get_pubkey(issuer.get()),
                                                                           &EVP_PKEY_free};
            if (issuer_key && X509_CRL_verify(candidate.value.get(), issuer_key.get()) == 1)
            {
                signature_valid = true;
                break;
            }
            ERR_clear_error();
        }
        if (!signature_valid)
            continue;

        for (int index = 0; index < sk_X509_num(verified_path); ++index)
        {
            auto* certificate = sk_X509_value(verified_path, index);
            if (certificate == nullptr ||
                X509_NAME_cmp(X509_CRL_get_issuer(candidate.value.get()), X509_get_issuer_name(certificate)) != 0)
                continue;

            X509_REVOKED* revoked = nullptr;
            if (X509_CRL_get0_by_serial(candidate.value.get(), &revoked, X509_get_serialNumber(certificate)) == 1)
                return true;
        }
    }
    return false;
}

}  // namespace score::crypto::daemon::provider::openssl::detail

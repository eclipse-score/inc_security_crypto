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

#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/cert_verification/openssl_cert_verification_handler.hpp"
#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/daemon/provider/cert_management/cert_types.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/cert_verification/detail/openssl_crl_selection.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/cert_verification/detail/openssl_revocation_coverage.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/cert_verification/detail/openssl_verify_result_mapping.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/cert_verification/detail/openssl_x509_utils.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/cert_verification/cert_verification_executor.hpp"
#include "score/mw/log/logging.h"

#include <openssl/err.h>
#include <openssl/x509.h>

#include <ctime>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{

namespace
{

constexpr std::string_view LOG_PREFIX = "[OPENSSL_CERT_VERIFY] ";
using Error = common::DaemonErrorCode;
namespace openssl_detail = ::score::crypto::daemon::provider::openssl::detail;
using openssl_detail::BuildFingerprintIndex;
using openssl_detail::CertSptr;
using openssl_detail::CertToX509;
using openssl_detail::FingerprintOf;
using openssl_detail::MapX509Error;
using openssl_detail::MapX509OperationError;
using openssl_detail::ParsedCrl;
using openssl_detail::RevocationCoverageState;
using openssl_detail::UniqueStackX509;
using openssl_detail::UniqueX509;
using openssl_detail::UniqueX509Store;
using openssl_detail::UniqueX509StoreCtx;
using openssl_detail::VerifyCrlCoverageCallback;

}  // namespace

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

OpenSslCertVerificationHandler::OpenSslCertVerificationHandler(
    std::unique_ptr<score_provider::operations::cert_verification::CertVerificationExecutor> executor,
    std::shared_ptr<::score::crypto::daemon::provider::cert_management::ICertParser> cert_parser,
    std::shared_ptr<::score::crypto::daemon::cert_management::CertManagementService> service)
    : ScoreCertVerificationHandler{std::move(executor), std::move(cert_parser), std::move(service)}
{
}

// ---------------------------------------------------------------------------
// DoVerify — OpenSSL X509_STORE_CTX chain verification
// ---------------------------------------------------------------------------

Expected<OpenSslCertVerificationHandler::VerifyOutcome, common::DaemonErrorCode>
OpenSslCertVerificationHandler::DoVerify(const VerificationInput& input)
{
    if (!input.leaf)
    {
        score::mw::log::LogError() << LOG_PREFIX << "DoVerify: no leaf certificate";
        return make_unexpected(Error::kInvalidArgument);
    }
    if (input.trusted.empty())
    {
        score::mw::log::LogWarn() << LOG_PREFIX << "DoVerify: no trust anchors configured";
        return VerifyOutcome{static_cast<uint8_t>(::score::crypto::CertVerifyResult::kNoRootFound), {}, {}};
    }

    // Build fingerprint index for chain reconstruction after verification.
    auto fp_index = BuildFingerprintIndex(input.leaf, input.chain, input.additional, input.trusted);
    std::vector<CertSptr> issuer_candidates;
    issuer_candidates.push_back(input.leaf);
    issuer_candidates.insert(issuer_candidates.end(), input.chain.begin(), input.chain.end());
    issuer_candidates.insert(issuer_candidates.end(), input.additional.begin(), input.additional.end());
    issuer_candidates.insert(issuer_candidates.end(), input.trusted.begin(), input.trusted.end());

    // --- X509_STORE: trusted anchors ---
    UniqueX509Store store(X509_STORE_new());
    if (!store)
    {
        score::mw::log::LogError() << LOG_PREFIX << "DoVerify: X509_STORE_new failed";
        return make_unexpected(Error::kInternalError);
    }

    // Standalone trusted certificates are anchors by definition and may be
    // intermediates. In trust-store mode, partial-chain validation is only
    // enabled for kTrustStoreTerminated.
    if (!input.trust_store_node_id.has_value() || input.chain_termination_policy != 0U)
        X509_STORE_set_flags(store.get(), X509_V_FLAG_PARTIAL_CHAIN);

    for (const auto& anchor : input.trusted)
    {
        if (!anchor)
            continue;
        auto x = CertToX509(*anchor);
        if (!x)
        {
            score::mw::log::LogWarn() << LOG_PREFIX << "DoVerify: failed to parse a trust anchor, skipping";
            continue;
        }
        // X509_STORE_add_cert increments the ref count; x is still our responsibility.
        if (X509_STORE_add_cert(store.get(), x.get()) != 1)
        {
            const auto err = ERR_peek_last_error();
            // X509_R_CERT_ALREADY_IN_HASH_TABLE means we already have this cert — not an error.
            if (ERR_GET_REASON(err) != X509_R_CERT_ALREADY_IN_HASH_TABLE)
            {
                score::mw::log::LogWarn() << LOG_PREFIX << "DoVerify: X509_STORE_add_cert failed (ignored)";
            }
            ERR_clear_error();
        }
        // x freed here — store holds its own reference
    }

    // --- Parse leaf ---
    UniqueX509 leaf_x509 = CertToX509(*input.leaf);
    if (!leaf_x509)
    {
        score::mw::log::LogError() << LOG_PREFIX << "DoVerify: failed to parse leaf certificate";
        return make_unexpected(Error::kCertificateParsingFailed);
    }

    // --- Untrusted intermediates stack (chain + additional, deduplicated by pointer/fingerprint) ---
    UniqueStackX509 untrusted(sk_X509_new_null());
    if (!untrusted)
        return make_unexpected(Error::kInternalError);

    auto push_intermediate = [&](const CertSptr& c) {
        if (!c)
            return;
        auto x = CertToX509(*c);
        if (!x)
            return;
        sk_X509_push(untrusted.get(), x.release());  // stack takes ownership
    };

    for (const auto& c : input.chain)
        push_intermediate(c);
    for (const auto& c : input.additional)
        push_intermediate(c);

    common::OwnedBuffer selected_crl_metadata;
    std::vector<ParsedCrl> selected_crls;

    // --- Revocation check policy (must be applied to the store before CTX init) ---
    using RevPol = ::score::crypto::daemon::provider::cert_management::RevocationCheckPolicy;
    switch (static_cast<RevPol>(input.revocation_policy))
    {
        case RevPol::kNone:
            break;  // no revocation check — default
        case RevPol::kCrlOnly:
        {
            auto selected_res = openssl_detail::SelectCrlsPerIssuer(input.crls, issuer_candidates);
            if (!selected_res.has_value())
                return make_unexpected(selected_res.error());
            selected_crls = std::move(selected_res.value());

            for (auto& candidate : selected_crls)
            {
                if (X509_STORE_add_crl(store.get(), candidate.value.get()) != 1)
                {
                    ERR_clear_error();
                    score::mw::log::LogWarn() << LOG_PREFIX << "DoVerify: selected CRL could not be added";
                    continue;
                }
            }
            X509_STORE_set_flags(store.get(), X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
            break;
        }
        case RevPol::kOcspOnly:
        case RevPol::kOcspWithCrlFallback:
            // OCSP requires a separate responder URL and HTTP client — deferred.
            return make_unexpected(Error::kUnsupportedOperation);
    }

    // --- X509_STORE_CTX ---
    UniqueX509StoreCtx ctx(X509_STORE_CTX_new());
    if (!ctx)
    {
        score::mw::log::LogError() << LOG_PREFIX << "DoVerify: X509_STORE_CTX_new failed";
        return make_unexpected(Error::kInternalError);
    }

    if (X509_STORE_CTX_init(ctx.get(), store.get(), leaf_x509.get(), untrusted.get()) != 1)
    {
        score::mw::log::LogError() << LOG_PREFIX << "DoVerify: X509_STORE_CTX_init failed";
        return make_unexpected(Error::kInternalError);
    }

    // Verification time override — per-instance, NOT global OpenSSL state.
    // Each DoVerify() creates its own X509_STORE_CTX; parallel contexts are fully isolated.
    if (input.verification_time_epoch_s.has_value())
    {
        X509_STORE_CTX_set_time(ctx.get(), 0U, static_cast<time_t>(*input.verification_time_epoch_s));
    }

    RevocationCoverageState coverage_state;
    coverage_state.best_effort =
        input.revocation_coverage_policy == ::score::crypto::RevocationCoveragePolicy::kBestEffort;
    if (static_cast<RevPol>(input.revocation_policy) == RevPol::kCrlOnly)
    {
        X509_STORE_CTX_set_app_data(ctx.get(), &coverage_state);
        X509_STORE_CTX_set_verify_cb(ctx.get(), VerifyCrlCoverageCallback);
    }

    const auto collectSelectedCrlMetadata = [&]() {
        if (input.evidence_mode != score::crypto::VerificationEvidenceMode::kChainAndCrl)
            return;
        selected_crl_metadata =
            openssl_detail::EncodeSelectedCrlMetadata(selected_crls, X509_STORE_CTX_get0_chain(ctx.get()));
    };

    const auto has_stale_revocation_entry = [&]() {
        if (static_cast<RevPol>(input.revocation_policy) != RevPol::kCrlOnly)
            return false;
        const auto verification_time =
            input.verification_time_epoch_s.value_or(static_cast<int64_t>(std::time(nullptr)));
        return openssl_detail::HasStaleRevocationEntry(
            selected_crls, issuer_candidates, X509_STORE_CTX_get0_chain(ctx.get()), verification_time);
    };

    // --- Verify ---
    const int result = X509_verify_cert(ctx.get());
    if (result != 1)
    {
        collectSelectedCrlMetadata();
        const int verify_err = X509_STORE_CTX_get_error(ctx.get());
        score::mw::log::LogWarn() << LOG_PREFIX << "DoVerify: verification failed: "
                                  << std::string_view{X509_verify_cert_error_string(verify_err)}
                                  << " (code=" << verify_err << ")";
        if (verify_err == X509_V_ERR_CERT_REVOKED && has_stale_revocation_entry())
        {
            return VerifyOutcome{static_cast<uint8_t>(::score::crypto::CertVerifyResult::kRevocationStatusUnavailable),
                                 {},
                                 std::move(selected_crl_metadata)};
        }
        // Return a VerifyOutcome with a non-zero result_code; chain is empty.
        const auto mapped_result = MapX509Error(verify_err);
        if (!mapped_result.has_value())
            return make_unexpected(MapX509OperationError(verify_err));
        return VerifyOutcome{*mapped_result, {}, std::move(selected_crl_metadata)};
    }

    if (has_stale_revocation_entry())
    {
        collectSelectedCrlMetadata();
        return VerifyOutcome{static_cast<uint8_t>(::score::crypto::CertVerifyResult::kRevocationStatusUnavailable),
                             {},
                             std::move(selected_crl_metadata)};
    }

    if (input.evidence_mode == score::crypto::VerificationEvidenceMode::kNone)
    {
        return VerifyOutcome{static_cast<uint8_t>(::score::crypto::CertVerifyResult::kValid), {}, {}};
    }

    collectSelectedCrlMetadata();

    // --- Extract verified chain (leaf first) ---
    STACK_OF(X509)* chain_sk = X509_STORE_CTX_get0_chain(ctx.get());
    std::vector<CertSptr> verified;
    verified.reserve(static_cast<std::size_t>(sk_X509_num(chain_sk)));

    for (int i = 0; i < sk_X509_num(chain_sk); ++i)
    {
        X509* x = sk_X509_value(chain_sk, i);
        const std::string fp = FingerprintOf(x);
        if (fp.empty())
        {
            score::mw::log::LogWarn() << LOG_PREFIX << "DoVerify: could not fingerprint chain cert at index " << i;
            continue;
        }
        const auto it = fp_index.find(fp);
        if (it != fp_index.end())
        {
            verified.push_back(it->second);
        }
        else
        {
            // Trust-store anchor that was not in any of the client-supplied input sets.
            score::mw::log::LogDebug() << LOG_PREFIX << "DoVerify: chain cert at index " << i
                                       << " is a trust-store-only anchor (not in client input)";
        }
    }

    score::mw::log::LogVerbose() << LOG_PREFIX << "DoVerify: success, chain length=" << verified.size();
    return VerifyOutcome{static_cast<uint8_t>(::score::crypto::CertVerifyResult::kValid),
                         std::move(verified),
                         std::move(selected_crl_metadata)};
}

}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler

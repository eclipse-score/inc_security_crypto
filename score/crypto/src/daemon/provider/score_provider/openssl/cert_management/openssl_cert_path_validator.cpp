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

#include "score/crypto/src/daemon/provider/score_provider/openssl/cert_management/openssl_cert_path_validator.hpp"

#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/cert_management/detail/openssl_crl_selection.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/cert_management/detail/openssl_revocation_coverage.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/cert_management/detail/openssl_verify_result_mapping.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/cert_management/detail/openssl_x509_utils.hpp"
#include "score/mw/log/logging.h"

#include <openssl/err.h>
#include <openssl/x509.h>

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace score::crypto::daemon::provider::score_provider::openssl
{

namespace
{

constexpr std::string_view kLogPrefix{"[OPENSSL_CERT_PATH] "};
namespace openssl_detail = ::score::crypto::daemon::provider::openssl::detail;
using Error = common::DaemonErrorCode;
using CertSptr = openssl_detail::CertSptr;
using ParsedCrl = openssl_detail::ParsedCrl;
using RevocationCheck = ::score::crypto::RevocationCheckPolicy;
using RevocationCoverage = ::score::crypto::RevocationCoveragePolicy;
using ChainTermination = ::score::crypto::ChainTerminationPolicy;
using CertVerifyResult = ::score::crypto::CertVerifyResult;
using PathValidationRequest = ::score::crypto::daemon::provider::cert_management::PathValidationRequest;
using PathValidationResult = ::score::crypto::daemon::provider::cert_management::PathValidationResult;
using openssl_detail::RevocationCoverageState;
using openssl_detail::UniqueStackX509;
using openssl_detail::UniqueX509;
using openssl_detail::UniqueX509Store;
using openssl_detail::UniqueX509StoreCtx;

// Returns nullptr if the store cannot be allocated; unparseable anchors are left out and counted in skipped.
UniqueX509Store BuildTrustStore(const PathValidationRequest& request, std::size_t& skipped)
{
    UniqueX509Store store{X509_STORE_new()};
    if (!store)
        return nullptr;

    // Partial-chain validation lets a trust anchor terminate a path below its own issuer. It is enabled only for
    // kTrustStoreTerminated; kRootRequired paths must end at a self-signed certificate.
    if (request.chain_termination == ChainTermination::kTrustStoreTerminated)
        X509_STORE_set_flags(store.get(), X509_V_FLAG_PARTIAL_CHAIN);

    for (const auto& anchor : request.trust_anchors)
    {
        if (!anchor)
        {
            ++skipped;
            continue;
        }
        const UniqueX509 anchor_x509 = openssl_detail::CertToX509(*anchor);
        if (!anchor_x509)
        {
            score::mw::log::LogError() << kLogPrefix << "failed to parse a trust anchor, skipping";
            ++skipped;
            continue;
        }
        // X509_STORE_add_cert takes its own reference; anchor_x509 is released when this scope ends.
        if (X509_STORE_add_cert(store.get(), anchor_x509.get()) != 1)
        {
            // A certificate that is already in the store is not a failure.
            if (ERR_GET_REASON(ERR_peek_last_error()) != X509_R_CERT_ALREADY_IN_HASH_TABLE)
                score::mw::log::LogWarn() << kLogPrefix << "X509_STORE_add_cert failed for a trust anchor";
            ERR_clear_error();
        }
    }
    return store;
}

// Builds the stack of presented intermediates. Returns nullptr if the stack cannot be allocated.
UniqueStackX509 BuildUntrustedStack(const std::vector<CertSptr>& untrusted, std::size_t& skipped)
{
    UniqueStackX509 stack{sk_X509_new_null()};
    if (!stack)
        return nullptr;

    for (const auto& certificate : untrusted)
    {
        if (!certificate)
        {
            ++skipped;
            continue;
        }
        UniqueX509 x509 = openssl_detail::CertToX509(*certificate);
        if (!x509)
        {
            score::mw::log::LogError() << kLogPrefix << "failed to parse an intermediate certificate, skipping";
            ++skipped;
            continue;
        }
        if (sk_X509_push(stack.get(), x509.get()) == 0)
            return nullptr;
        // The stack holds the reference from here on.
        static_cast<void>(x509.release());
    }
    return stack;
}

// Adds the selected CRLs to the store and enables CRL checking; returns only the CRLs the store accepted.
score::crypto::Expected<std::vector<ParsedCrl>, Error> ConfigureCrlChecks(
    const PathValidationRequest& request,
    const std::vector<CertSptr>& issuer_candidates,
    X509_STORE* store)
{
    auto selected = openssl_detail::SelectCrlsPerIssuer(request.crls, issuer_candidates);
    if (!selected.has_value())
        return score::crypto::make_unexpected(selected.error());

    std::vector<ParsedCrl> applied;
    for (auto& crl : selected.value())
    {
        if (X509_STORE_add_crl(store, crl.value.get()) != 1)
        {
            ERR_clear_error();
            score::mw::log::LogWarn() << kLogPrefix << "selected CRL could not be added to the store, not applied";
            continue;
        }
        applied.push_back(std::move(crl));
    }
    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
    return applied;
}

// Maps the verified chain back to the caller's certificate objects, leaf first. Every chain entry must match a
// supplied certificate; a mismatch means the index and the path disagree, so no chain is returned.
score::crypto::Expected<std::vector<CertSptr>, Error> ExtractChain(
    STACK_OF(X509) * chain,
    const std::unordered_map<std::string, CertSptr>& fingerprint_index)
{
    std::vector<CertSptr> verified;
    if (chain == nullptr)
        return verified;

    verified.reserve(static_cast<std::size_t>(sk_X509_num(chain)));
    for (int i = 0; i < sk_X509_num(chain); ++i)
    {
        const std::string fingerprint = openssl_detail::FingerprintOf(sk_X509_value(chain, i));
        const auto found = fingerprint_index.find(fingerprint);
        if (fingerprint.empty() || found == fingerprint_index.end())
        {
            score::mw::log::LogError() << kLogPrefix << "verified chain certificate at index " << i
                                       << " does not match a supplied certificate";
            return score::crypto::make_unexpected(Error::kInternalError);
        }
        verified.push_back(found->second);
    }
    return verified;
}

}  // namespace

score::crypto::Expected<PathValidationResult, Error> OpenSslCertPathValidator::Validate(
    const PathValidationRequest& request)
{
    PathValidationResult outcome;
    if (!request.leaf)
    {
        score::mw::log::LogError() << kLogPrefix << "no leaf certificate";
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }
    if (request.trust_anchors.empty())
    {
        // Without anchors no path can be established. That is a verdict, not an operation failure.
        score::mw::log::LogWarn() << kLogPrefix << "no trust anchors supplied";
        outcome.result = CertVerifyResult::kNoRootFound;
        return outcome;
    }

    // Every certificate that may issue a CRL or appear on the path.
    std::vector<CertSptr> issuer_candidates;
    issuer_candidates.reserve(1U + request.untrusted.size() + request.trust_anchors.size());
    issuer_candidates.push_back(request.leaf);
    issuer_candidates.insert(issuer_candidates.end(), request.untrusted.begin(), request.untrusted.end());
    issuer_candidates.insert(issuer_candidates.end(), request.trust_anchors.begin(), request.trust_anchors.end());
    const auto fingerprint_index =
        openssl_detail::BuildFingerprintIndex(request.leaf, request.untrusted, request.trust_anchors);

    std::size_t skipped_inputs = 0U;
    UniqueX509Store store = BuildTrustStore(request, skipped_inputs);
    if (!store)
    {
        score::mw::log::LogError() << kLogPrefix << "X509_STORE_new failed";
        return score::crypto::make_unexpected(Error::kInternalError);
    }

    UniqueX509 leaf_x509 = openssl_detail::CertToX509(*request.leaf);
    if (!leaf_x509)
    {
        score::mw::log::LogError() << kLogPrefix << "failed to parse the leaf certificate";
        return score::crypto::make_unexpected(Error::kCertificateParsingFailed);
    }

    UniqueStackX509 untrusted = BuildUntrustedStack(request.untrusted, skipped_inputs);
    if (!untrusted)
    {
        score::mw::log::LogError() << kLogPrefix << "failed to allocate the intermediate stack";
        return score::crypto::make_unexpected(Error::kInternalError);
    }

    // The revocation policy is applied to the store before the verification context is initialized.
    std::vector<ParsedCrl> selected_crls;
    switch (request.revocation_check)
    {
        case RevocationCheck::kNone:
            break;
        case RevocationCheck::kCrlOnly:
        {
            auto configured = ConfigureCrlChecks(request, issuer_candidates, store.get());
            if (!configured.has_value())
                return score::crypto::make_unexpected(configured.error());
            selected_crls = std::move(configured.value());
            break;
        }
        case RevocationCheck::kOcspOnly:
        case RevocationCheck::kOcspWithCrlFallback:
            // OCSP needs a responder location and an HTTP client; this validator performs CRL checks only.
            return score::crypto::make_unexpected(Error::kUnsupportedOperation);
    }

    // The coverage state is declared before the context so that it outlives the context's app data pointer.
    RevocationCoverageState coverage_state{request.revocation_coverage == RevocationCoverage::kBestEffort};

    UniqueX509StoreCtx ctx{X509_STORE_CTX_new()};
    if (!ctx)
    {
        score::mw::log::LogError() << kLogPrefix << "X509_STORE_CTX_new failed";
        return score::crypto::make_unexpected(Error::kInternalError);
    }
    if (X509_STORE_CTX_init(ctx.get(), store.get(), leaf_x509.get(), untrusted.get()) != 1)
    {
        score::mw::log::LogError() << kLogPrefix << "X509_STORE_CTX_init failed";
        return score::crypto::make_unexpected(Error::kInternalError);
    }

    // The verification time is fixed once so OpenSSL and the stale-CRL check judge the same instant. The override
    // applies to this context only, so concurrent validations do not share it.
    const auto verification_time =
        request.verification_time_epoch_s.value_or(static_cast<std::int64_t>(std::time(nullptr)));
    X509_STORE_CTX_set_time(ctx.get(), 0U, static_cast<time_t>(verification_time));
    if (request.revocation_check == RevocationCheck::kCrlOnly)
    {
        X509_STORE_CTX_set_app_data(ctx.get(), &coverage_state);
        X509_STORE_CTX_set_verify_cb(ctx.get(), openssl_detail::VerifyCrlCoverageCallback);
    }

    const int verified = X509_verify_cert(ctx.get());
    const int verify_error = verified == 1 ? X509_V_OK : X509_STORE_CTX_get_error(ctx.get());
    outcome.selected_crl_metadata =
        openssl_detail::AppliedCrlMetadata(selected_crls, X509_STORE_CTX_get0_chain(ctx.get()));

    CertVerifyResult verdict = CertVerifyResult::kValid;
    if (verified != 1)
    {
        score::mw::log::LogWarn() << kLogPrefix << "verification failed: "
                                  << std::string_view{X509_verify_cert_error_string(verify_error)}
                                  << " (code=" << verify_error << ")";
        const auto mapped = openssl_detail::MapX509Error(verify_error);
        if (!mapped.has_value())
            return score::crypto::make_unexpected(openssl_detail::MapX509OperationError(verify_error));
        verdict = mapped.value();
    }

    // A stale CRL listing a certificate is indeterminate; it makes a revoked or valid result unavailable.
    const bool revocation_outcome_applies = verified == 1 || verify_error == X509_V_ERR_CERT_REVOKED;
    if (revocation_outcome_applies &&
        openssl_detail::HasStaleRevocationEntry(selected_crls, X509_STORE_CTX_get0_chain(ctx.get()), verification_time))
    {
        verdict = CertVerifyResult::kRevocationStatusUnavailable;
    }

    // Verdicts that a missing issuer or anchor can cause are withheld; definite verdicts are reported as-is.
    const bool input_dependent = verdict == CertVerifyResult::kChainIncomplete ||
                                 verdict == CertVerifyResult::kNoRootFound ||
                                 verdict == CertVerifyResult::kRevocationStatusUnavailable;
    if (input_dependent && skipped_inputs != 0U)
    {
        score::mw::log::LogError() << kLogPrefix << "verdict withheld: " << skipped_inputs
                                   << " certificate input(s) could not be parsed";
        return score::crypto::make_unexpected(Error::kCertificateParsingFailed);
    }

    outcome.result = verdict;
    if (verdict != CertVerifyResult::kValid)
        return outcome;

    auto chain = ExtractChain(X509_STORE_CTX_get0_chain(ctx.get()), fingerprint_index);
    if (!chain.has_value())
        return score::crypto::make_unexpected(chain.error());
    outcome.chain = std::move(chain.value());
    score::mw::log::LogVerbose() << kLogPrefix << "verification succeeded, chain length=" << outcome.chain.size();
    return outcome;
}

}  // namespace score::crypto::daemon::provider::score_provider::openssl

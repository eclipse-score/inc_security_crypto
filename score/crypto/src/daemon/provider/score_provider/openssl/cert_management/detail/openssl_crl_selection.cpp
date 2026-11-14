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

#include "score/crypto/src/daemon/provider/score_provider/openssl/cert_management/detail/openssl_crl_selection.hpp"

#include "score/crypto/src/api/types/certificate.hpp"
#include "score/mw/log/logging.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <algorithm>
#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace score::crypto::daemon::provider::openssl::detail
{

namespace
{

constexpr std::string_view kLogPrefix{"[OPENSSL_CERT_PATH] "};
using Error = common::DaemonErrorCode;

// Returns the fingerprint of the candidate whose key verifies the CRL signature, or nullopt if none does.
// A name match alone does not establish the issuer.
score::crypto::Expected<std::optional<Sha256Digest>, Error> IssuerFingerprint(X509_CRL* crl,
                                                                              const std::vector<CertSptr>& candidates)
{
    if (crl == nullptr)
        return score::crypto::make_unexpected(Error::kInvalidArgument);

    const auto* issuer = X509_CRL_get_issuer(crl);
    if (issuer == nullptr)
        return score::crypto::make_unexpected(Error::kCertificateParsingFailed);

    for (const auto& candidate : candidates)
    {
        if (!candidate)
            continue;
        const UniqueX509 x509 = CertToX509(*candidate);
        if (!x509 || X509_NAME_cmp(issuer, X509_get_subject_name(x509.get())) != 0)
            continue;

        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key{X509_get_pubkey(x509.get()), &EVP_PKEY_free};
        if (!key || X509_CRL_verify(crl, key.get()) != 1)
        {
            ERR_clear_error();
            continue;
        }

        const auto fingerprint = candidate->GetFingerprint();
        Sha256Digest result{};
        if (fingerprint.size() != result.size())
            return score::crypto::make_unexpected(Error::kInvalidArgument);

        std::copy(fingerprint.begin(), fingerprint.end(), result.begin());
        return std::optional<Sha256Digest>{result};
    }
    return std::optional<Sha256Digest>{};
}

// Keys the per-issuer selection by the issuer certificate fingerprint.
std::string IssuerKey(const score::crypto::CrlMetadata& metadata)
{
    return std::string(reinterpret_cast<const char*>(metadata.issuer_fingerprint.data()),
                       metadata.issuer_fingerprint.size());
}

}  // namespace

score::crypto::Expected<std::vector<ParsedCrl>, common::DaemonErrorCode> SelectCrlsPerIssuer(
    const std::vector<std::shared_ptr<const ::score::crypto::daemon::cert_management::CrlData>>& crls,
    const std::vector<CertSptr>& issuer_candidates)
{
    std::vector<ParsedCrl> candidates;
    for (const auto& crl_data : crls)
    {
        if (!crl_data)
        {
            score::mw::log::LogWarn() << kLogPrefix << "null CRL entry, skipping";
            continue;
        }

        // The format is the one the CRL was stored with; it is never assumed.
        UniqueX509Crl crl = ParseX509Crl(crl_data->bytes.data(), crl_data->bytes.size(), crl_data->format);
        if (!crl)
        {
            score::mw::log::LogWarn() << kLogPrefix << "failed to parse a CRL, skipping";
            continue;
        }

        const auto issuer_fingerprint = IssuerFingerprint(crl.get(), issuer_candidates);
        if (!issuer_fingerprint.has_value())
        {
            score::mw::log::LogError() << kLogPrefix << "invalid CRL issuer fingerprint";
            return score::crypto::make_unexpected(issuer_fingerprint.error());
        }
        if (!issuer_fingerprint.value().has_value())
        {
            score::mw::log::LogWarn() << kLogPrefix << "CRL is not signed by a supplied issuer, skipping";
            continue;
        }

        score::crypto::CrlMetadata metadata{};
        if (!ReadCrlMetadata(crl.get(), metadata))
        {
            score::mw::log::LogError() << kLogPrefix << "failed to fingerprint CRL";
            return score::crypto::make_unexpected(Error::kOperationFailed);
        }
        if (crl_data->metadata.has_value() && crl_data->metadata->fingerprint != metadata.fingerprint)
        {
            score::mw::log::LogWarn() << kLogPrefix << "CRL metadata does not match the CRL bytes, skipping";
            continue;
        }

        metadata.issuer_fingerprint = issuer_fingerprint.value().value();
        candidates.push_back(ParsedCrl{std::move(crl), metadata});
    }

    // winner_by_issuer maps each issuer to the index of its selected CRL in candidates.
    std::unordered_map<std::string, std::size_t> winner_by_issuer;
    for (std::size_t i = 0U; i < candidates.size(); ++i)
    {
        const auto& candidate = candidates[i].metadata;
        const auto key = IssuerKey(candidate);
        const auto current = winner_by_issuer.find(key);
        if (current == winner_by_issuer.end())
        {
            winner_by_issuer.emplace(key, i);
            continue;
        }

        const auto& incumbent = candidates[current->second].metadata;
        const bool has_higher_number =
            candidate.crl_number != 0U && (incumbent.crl_number == 0U || candidate.crl_number > incumbent.crl_number);
        const bool same_number_newer_time =
            candidate.crl_number == incumbent.crl_number && candidate.this_update > incumbent.this_update;
        if (has_higher_number || same_number_newer_time)
            current->second = i;
    }

    std::vector<ParsedCrl> selected_crls;
    for (std::size_t i = 0U; i < candidates.size(); ++i)
    {
        const auto winner = winner_by_issuer.find(IssuerKey(candidates[i].metadata));
        if (winner != winner_by_issuer.end() && winner->second == i)
            selected_crls.push_back(std::move(candidates[i]));
    }
    return selected_crls;
}

std::vector<score::crypto::CrlMetadata> AppliedCrlMetadata(const std::vector<ParsedCrl>& selected,
                                                           STACK_OF(X509) * chain)
{
    std::vector<score::crypto::CrlMetadata> applied;
    if (chain == nullptr)
        return applied;

    for (const auto& candidate : selected)
    {
        bool matches_path = false;
        for (int i = 0; i < sk_X509_num(chain); ++i)
        {
            X509* certificate = sk_X509_value(chain, i);
            if (certificate != nullptr &&
                X509_NAME_cmp(X509_CRL_get_issuer(candidate.value.get()), X509_get_issuer_name(certificate)) == 0)
            {
                matches_path = true;
                break;
            }
        }
        if (matches_path)
            applied.push_back(candidate.metadata);
    }
    return applied;
}

}  // namespace score::crypto::daemon::provider::openssl::detail

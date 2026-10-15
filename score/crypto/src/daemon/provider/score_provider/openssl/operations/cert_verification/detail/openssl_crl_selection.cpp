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

#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/cert_verification/detail/openssl_crl_selection.hpp"
#include "score/crypto/src/api/types/certificate.hpp"
#include "score/mw/log/logging.h"

#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace score::crypto::daemon::provider::openssl::detail
{

namespace
{

constexpr std::string_view LOG_PREFIX = "[OPENSSL_CERT_VERIFY] ";
using Error = common::DaemonErrorCode;

Expected<std::optional<Sha256Digest>, Error> IssuerFingerprint(const X509_CRL* crl,
                                                               const std::vector<CertSptr>& candidates)
{
    if (crl == nullptr)
        return make_unexpected(Error::kInvalidArgument);

    const auto* issuer = X509_CRL_get_issuer(crl);
    if (issuer == nullptr)
        return make_unexpected(Error::kCertificateParsingFailed);

    for (const auto& candidate : candidates)
    {
        if (!candidate)
            continue;
        auto x509 = CertToX509(*candidate);
        if (x509 && X509_NAME_cmp(issuer, X509_get_subject_name(x509.get())) == 0)
        {
            const auto fingerprint = candidate->GetFingerprint();
            Sha256Digest result{};
            if (fingerprint.size() != result.size())
                return make_unexpected(Error::kInvalidArgument);

            std::copy(fingerprint.begin(), fingerprint.end(), result.begin());
            return result;
        }
    }
    return std::nullopt;
}

}  // namespace

Expected<std::vector<ParsedCrl>, common::DaemonErrorCode> SelectCrlsPerIssuer(
    const std::vector<::score::crypto::daemon::cert_management::CrlEntry>& crls,
    const std::vector<CertSptr>& issuer_candidates)
{
    std::vector<ParsedCrl> candidates;
    for (const auto& crl_entry : crls)
    {
        UniqueX509Crl crl = ParseX509Crl(crl_entry.bytes.data(), crl_entry.bytes.size(), crl_entry.format);
        if (!crl)
        {
            score::mw::log::LogWarn() << LOG_PREFIX << "failed to parse a CRL, skipping";
            continue;
        }
        const auto issuer_fp_res = IssuerFingerprint(crl.get(), issuer_candidates);
        if (!issuer_fp_res.has_value())
        {
            score::mw::log::LogError() << LOG_PREFIX << "invalid CRL issuer fingerprint";
            return make_unexpected(issuer_fp_res.error());
        }
        if (!issuer_fp_res.value().has_value())
        {
            score::mw::log::LogWarn() << LOG_PREFIX << "CRL issuer not present in verification inputs";
            continue;
        }

        score::crypto::CrlMetadata metadata{};
        if (!ReadCrlMetadata(crl.get(), metadata))
        {
            score::mw::log::LogError() << LOG_PREFIX << "failed to fingerprint CRL";
            return make_unexpected(Error::kOperationFailed);
        }
        metadata.issuer_fingerprint = issuer_fp_res.value().value();
        candidates.push_back(ParsedCrl{std::move(crl), metadata});
    }

    std::unordered_map<std::string, std::size_t> selected;
    for (std::size_t i = 0U; i < candidates.size(); ++i)
    {
        const auto& candidate = candidates[i].metadata;
        const auto key = std::string(reinterpret_cast<const char*>(candidate.issuer_fingerprint.data()),
                                     candidate.issuer_fingerprint.size());
        const auto current = selected.find(key);
        const auto& current_candidate = current == selected.end() ? candidate : candidates[current->second].metadata;
        const bool has_higher_number =
            candidate.crl_number != 0U && (current == selected.end() || current_candidate.crl_number == 0U ||
                                           candidate.crl_number > current_candidate.crl_number);
        const bool same_number_newer_time = candidate.crl_number == current_candidate.crl_number &&
                                            candidate.this_update > current_candidate.this_update;
        if (current == selected.end() || has_higher_number || same_number_newer_time)
        {
            selected[key] = i;
        }
    }

    std::vector<ParsedCrl> selected_crls;
    for (const auto& selected_entry : selected)
    {
        selected_crls.push_back(std::move(candidates[selected_entry.second]));
    }
    return selected_crls;
}

common::OwnedBuffer EncodeSelectedCrlMetadata(const std::vector<ParsedCrl>& selected, STACK_OF(X509) * chain)
{
    common::OwnedBuffer encoded_metadata;
    if (chain == nullptr)
        return encoded_metadata;

    for (const auto& candidate : selected)
    {
        bool matches_path = false;
        for (int i = 0; i < sk_X509_num(chain); ++i)
        {
            auto* certificate = sk_X509_value(chain, i);
            if (certificate != nullptr &&
                X509_NAME_cmp(X509_CRL_get_issuer(candidate.value.get()), X509_get_issuer_name(certificate)) == 0)
            {
                matches_path = true;
                break;
            }
        }
        if (!matches_path)
            continue;
        std::array<std::uint8_t, score::crypto::CrlMetadataWireLayout::kEntrySize> encoded{};
        score::crypto::CrlMetadataWireLayout::Encode(candidate.metadata, encoded);
        encoded_metadata.insert(encoded_metadata.end(), encoded.begin(), encoded.end());
    }
    return encoded_metadata;
}

}  // namespace score::crypto::daemon::provider::openssl::detail

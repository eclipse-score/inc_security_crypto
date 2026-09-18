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
#include "score/crypto/src/daemon/provider/cert_management/cert_types.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/cert_verification/cert_verification_executor.hpp"
#include "score/mw/log/logging.h"

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <array>
#include <ctime>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{

namespace
{

constexpr std::string_view LOG_PREFIX = "[OPENSSL_CERT_VERIFY] ";
using Error = common::DaemonErrorCode;
using CertObject = ::score::crypto::daemon::cert_management::CertObject;
using CertSptr = std::shared_ptr<CertObject>;

// ---------------------------------------------------------------------------
// RAII wrappers
// ---------------------------------------------------------------------------

struct X509Deleter
{
    void operator()(X509* p) const noexcept
    {
        X509_free(p);
    }
};
using UniqueX509 = std::unique_ptr<X509, X509Deleter>;

struct X509StoreDeleter
{
    void operator()(X509_STORE* p) const noexcept
    {
        X509_STORE_free(p);
    }
};
using UniqueX509Store = std::unique_ptr<X509_STORE, X509StoreDeleter>;

struct X509StoreCtxDeleter
{
    void operator()(X509_STORE_CTX* p) const noexcept
    {
        X509_STORE_CTX_free(p);
    }
};
using UniqueX509StoreCtx = std::unique_ptr<X509_STORE_CTX, X509StoreCtxDeleter>;

struct StackX509Deleter
{
    void operator()(STACK_OF(X509) * p) const noexcept
    {
        sk_X509_pop_free(p, X509_free);
    }
};
using UniqueStackX509 = std::unique_ptr<STACK_OF(X509), StackX509Deleter>;

struct X509CrlDeleter
{
    void operator()(X509_CRL* p) const noexcept
    {
        X509_CRL_free(p);
    }
};
using UniqueX509Crl = std::unique_ptr<X509_CRL, X509CrlDeleter>;

// ---------------------------------------------------------------------------
// Parse a CertObject into an X509* (DER or PEM).
// ---------------------------------------------------------------------------
UniqueX509 CertToX509(const CertObject& cert)
{
    const auto& raw = cert.GetRawBytes();
    if (raw.empty())
        return nullptr;

    if (cert.GetFormat() == score::crypto::FormatType::kDer)
    {
        const uint8_t* ptr = raw.data();
        return UniqueX509(d2i_X509(nullptr, &ptr, static_cast<long>(raw.size())));
    }

    // PEM path
    auto* raw_bio = BIO_new_mem_buf(raw.data(), static_cast<int>(raw.size()));
    if (raw_bio == nullptr)
        return nullptr;
    std::unique_ptr<BIO, decltype(&BIO_free)> bio{raw_bio, &BIO_free};
    return UniqueX509(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
}

// ---------------------------------------------------------------------------
// Compute SHA-256 fingerprint of an X509* (32 bytes in hex-free form).
// Returns empty string on failure.
// ---------------------------------------------------------------------------
std::string FingerprintOf(X509* x)
{
    std::array<uint8_t, SHA256_DIGEST_LENGTH> fp{};
    uint32_t fp_len = static_cast<uint32_t>(fp.size());
    if (X509_digest(x, EVP_sha256(), fp.data(), &fp_len) != 1 || fp_len != SHA256_DIGEST_LENGTH)
        return {};
    return std::string(reinterpret_cast<const char*>(fp.data()), fp_len);
}

Expected<std::array<std::uint8_t, 32U>, Error> DigestCrl(X509_CRL* crl)
{
    if (crl == nullptr)
        return make_unexpected(Error::kInvalidArgument);

    std::array<std::uint8_t, SHA256_DIGEST_LENGTH> result{};
    unsigned int length = static_cast<unsigned int>(result.size());
    if (X509_CRL_digest(crl, EVP_sha256(), result.data(), &length) != 1 || length != result.size())
        return make_unexpected(Error::kOperationFailed);
    return result;
}

std::int64_t Asn1TimeToEpoch(const ASN1_TIME* value)
{
    if (value == nullptr)
        return 0;
    std::tm calendar{};
    if (ASN1_TIME_to_tm(value, &calendar) != 1)
        return 0;
    return static_cast<std::int64_t>(timegm(&calendar));
}

std::uint64_t CrlNumber(X509_CRL* crl)
{
    int critical = 0;
    ASN1_INTEGER* number = static_cast<ASN1_INTEGER*>(X509_CRL_get_ext_d2i(crl, NID_crl_number, &critical, nullptr));
    if (number == nullptr)
        return 0U;
    std::unique_ptr<ASN1_INTEGER, decltype(&ASN1_INTEGER_free)> number_guard{number, &ASN1_INTEGER_free};
    BIGNUM* value = ASN1_INTEGER_to_BN(number, nullptr);
    if (value == nullptr || BN_is_negative(value) || BN_num_bits(value) > 64)
    {
        BN_free(value);
        return 0U;
    }
    std::uint8_t encoded[sizeof(std::uint64_t)]{};
    const int length = BN_bn2binpad(value, encoded, sizeof(encoded));
    BN_free(value);
    if (length != static_cast<int>(sizeof(encoded)))
        return 0U;
    std::uint64_t result = 0U;
    for (const auto byte : encoded)
        result = (result << 8U) | byte;
    return result;
}

Expected<std::optional<std::array<std::uint8_t, 32U>>, Error> IssuerFingerprint(X509_CRL* crl,
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
            if (fingerprint.size() != SHA256_DIGEST_LENGTH)
                return make_unexpected(Error::kInvalidArgument);

            std::array<std::uint8_t, SHA256_DIGEST_LENGTH> result{};
            std::copy(fingerprint.begin(), fingerprint.end(), result.begin());
            return result;
        }
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// Map X509 verification error code to CertVerifyResult numeric value.
// ---------------------------------------------------------------------------
uint8_t MapX509Error(int x509_err)
{
    using R = ::score::crypto::daemon::provider::cert_management::CertVerifyErrorCode;
    switch (x509_err)
    {
        case X509_V_ERR_CERT_HAS_EXPIRED:
            return static_cast<uint8_t>(R::kExpired);
        case X509_V_ERR_CERT_NOT_YET_VALID:
            return static_cast<uint8_t>(R::kNotYetValid);
        case X509_V_ERR_CERT_REVOKED:
            return static_cast<uint8_t>(R::kRevoked);
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
        case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
        case X509_V_ERR_CERT_UNTRUSTED:
            return static_cast<uint8_t>(R::kNoRootFound);
        case X509_V_ERR_CERT_CHAIN_TOO_LONG:
            return static_cast<uint8_t>(R::kChainIncomplete);
        case X509_V_ERR_CERT_SIGNATURE_FAILURE:
            return static_cast<uint8_t>(R::kSignatureInvalid);
        case X509_V_ERR_INVALID_PURPOSE:
            return static_cast<uint8_t>(R::kInvalidPurpose);
        case X509_V_ERR_UNABLE_TO_GET_CRL:
        case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
        case X509_V_ERR_CRL_SIGNATURE_FAILURE:
        case X509_V_ERR_CRL_NOT_YET_VALID:
        case X509_V_ERR_CRL_HAS_EXPIRED:
            return static_cast<uint8_t>(R::kUnknownError);
        default:
            return static_cast<uint8_t>(R::kUnknownError);
    }
}

// ---------------------------------------------------------------------------
// Build a fingerprint → CertSptr index from all input cert sets.
// ---------------------------------------------------------------------------
std::unordered_map<std::string, CertSptr> BuildFingerprintIndex(const CertSptr& leaf,
                                                                const std::vector<CertSptr>& chain,
                                                                const std::vector<CertSptr>& additional,
                                                                const std::vector<CertSptr>& trusted)
{
    std::unordered_map<std::string, CertSptr> idx;
    auto insert = [&](const CertSptr& c) {
        if (!c)
            return;
        const auto fp = c->GetFingerprint();  // span<const uint8_t>
        if (!fp.empty())
            idx.emplace(std::string(reinterpret_cast<const char*>(fp.data()), fp.size()), c);
    };
    insert(leaf);
    for (const auto& c : chain)
        insert(c);
    for (const auto& c : additional)
        insert(c);
    for (const auto& c : trusted)
        insert(c);
    return idx;
}

}  // namespace

Expected<common::OwnedBuffer, common::DaemonErrorCode> OpenSslCertVerificationHandler::EncodeCertificate(
    const CertSptr& cert,
    score::crypto::FormatType format) const
{
    if (!cert)
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    if (format != score::crypto::FormatType::kDer && format != score::crypto::FormatType::kPem)
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);

    auto x509 = CertToX509(*cert);
    if (!x509)
        return make_unexpected(common::DaemonErrorCode::kCertificateParsingFailed);

    if (format == score::crypto::FormatType::kDer)
    {
        const int size = i2d_X509(x509.get(), nullptr);
        if (size <= 0)
            return make_unexpected(common::DaemonErrorCode::kOperationFailed);

        common::OwnedBuffer output(static_cast<std::size_t>(size));
        unsigned char* cursor = output.data();
        if (i2d_X509(x509.get(), &cursor) != size)
            return make_unexpected(common::DaemonErrorCode::kOperationFailed);
        return output;
    }

    auto* raw_bio = BIO_new(BIO_s_mem());
    if (raw_bio == nullptr)
        return make_unexpected(common::DaemonErrorCode::kInternalError);
    std::unique_ptr<BIO, decltype(&BIO_free)> bio{raw_bio, &BIO_free};
    if (PEM_write_bio_X509(bio.get(), x509.get()) != 1)
        return make_unexpected(common::DaemonErrorCode::kOperationFailed);

    BUF_MEM* memory = nullptr;
    BIO_get_mem_ptr(bio.get(), &memory);
    if (memory == nullptr || memory->data == nullptr)
        return make_unexpected(common::DaemonErrorCode::kOperationFailed);
    return common::OwnedBuffer(memory->data, memory->data + memory->length);
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

OpenSslCertVerificationHandler::OpenSslCertVerificationHandler(
    std::unique_ptr<score_provider::operations::cert_verification::CertVerificationExecutor> executor,
    std::shared_ptr<::score::crypto::daemon::cert_management::CertManagementService> service)
    : ScoreCertVerificationHandler{std::move(executor), std::move(service)}
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
        score::mw::log::LogError() << LOG_PREFIX << "DoVerify: no trust anchors";
        return make_unexpected(Error::kInvalidArgument);
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
        return make_unexpected(Error::kInvalidArgument);
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
    struct ParsedCrl
    {
        UniqueX509Crl value;
        std::array<std::uint8_t, 32U> issuer_fingerprint{};
        std::array<std::uint8_t, 32U> crl_fingerprint{};
        std::int64_t this_update{0};
        std::int64_t next_update{0};
        std::uint64_t crl_number{0U};
    };
    std::vector<ParsedCrl> selected_crls;

    // --- Revocation check policy (must be applied to the store before CTX init) ---
    using RevPol = ::score::crypto::daemon::provider::cert_management::RevocationCheckPolicy;
    switch (static_cast<RevPol>(input.revocation_policy))
    {
        case RevPol::kNone:
            break;  // no revocation check — default
        case RevPol::kCrlOnly:
        {
            if (input.crls.empty())
            {
                score::mw::log::LogError() << LOG_PREFIX << "DoVerify: CRL check requested but no CRLs available";
                return make_unexpected(Error::kUnsupportedOperation);
            }
            bool any_loaded = false;
            std::vector<ParsedCrl> candidates;
            for (const auto& crl_entry : input.crls)
            {
                UniqueX509Crl crl;
                if (crl_entry.format == score::crypto::FormatType::kDer)
                {
                    const uint8_t* ptr = crl_entry.bytes.data();
                    crl.reset(d2i_X509_CRL(nullptr, &ptr, static_cast<long>(crl_entry.bytes.size())));
                }
                else
                {
                    auto* bio_raw = BIO_new_mem_buf(crl_entry.bytes.data(), static_cast<int>(crl_entry.bytes.size()));
                    if (bio_raw != nullptr)
                    {
                        std::unique_ptr<BIO, decltype(&BIO_free)> bio{bio_raw, &BIO_free};
                        crl.reset(PEM_read_bio_X509_CRL(bio.get(), nullptr, nullptr, nullptr));
                    }
                }
                if (!crl)
                {
                    score::mw::log::LogWarn() << LOG_PREFIX << "DoVerify: failed to parse a CRL, skipping";
                    continue;
                }
                const auto issuer_fp_res = IssuerFingerprint(crl.get(), issuer_candidates);
                if (!issuer_fp_res.has_value())
                {
                    score::mw::log::LogError() << LOG_PREFIX << "DoVerify: invalid CRL issuer fingerprint";
                    return make_unexpected(issuer_fp_res.error());
                }
                if (!issuer_fp_res.value().has_value())
                {
                    score::mw::log::LogWarn()
                        << LOG_PREFIX << "DoVerify: CRL issuer not present in verification inputs";
                    continue;
                }
                const auto crl_fp_res = DigestCrl(crl.get());
                if (!crl_fp_res.has_value())
                {
                    score::mw::log::LogError() << LOG_PREFIX << "DoVerify: failed to fingerprint CRL";
                    return make_unexpected(crl_fp_res.error());
                }
                const auto& issuer_fp = issuer_fp_res.value().value();
                const auto& crl_fp = crl_fp_res.value();
                const auto this_update = Asn1TimeToEpoch(X509_CRL_get0_lastUpdate(crl.get()));
                const auto next_update = Asn1TimeToEpoch(X509_CRL_get0_nextUpdate(crl.get()));
                const auto crl_number = CrlNumber(crl.get());
                candidates.push_back(
                    ParsedCrl{std::move(crl), issuer_fp, crl_fp, this_update, next_update, crl_number});
            }

            std::unordered_map<std::string, std::size_t> selected;
            for (std::size_t i = 0U; i < candidates.size(); ++i)
            {
                const auto key = std::string(reinterpret_cast<const char*>(candidates[i].issuer_fingerprint.data()),
                                             candidates[i].issuer_fingerprint.size());
                const auto current = selected.find(key);
                const auto& candidate = candidates[i];
                const auto& current_candidate = current == selected.end() ? candidate : candidates[current->second];
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

            for (const auto& selected_entry : selected)
            {
                selected_crls.push_back(std::move(candidates[selected_entry.second]));
            }
            for (auto& candidate : selected_crls)
            {
                if (X509_STORE_add_crl(store.get(), candidate.value.get()) != 1)
                {
                    ERR_clear_error();
                    score::mw::log::LogWarn() << LOG_PREFIX << "DoVerify: selected CRL could not be added";
                    continue;
                }
                any_loaded = true;
            }
            if (any_loaded)
            {
                X509_STORE_set_flags(store.get(), X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
            }
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

    const auto collectSelectedCrlMetadata = [&]() {
        if (input.evidence_mode != score::crypto::VerificationEvidenceMode::kChainAndCrl)
            return;
        auto* chain = X509_STORE_CTX_get0_chain(ctx.get());
        if (chain == nullptr)
            return;
        const auto append_i64 = [&selected_crl_metadata](std::int64_t value) {
            for (std::size_t i = 0U; i < sizeof(value); ++i)
                selected_crl_metadata.push_back(static_cast<std::uint8_t>(value >> (i * 8U)));
        };
        for (const auto& candidate : selected_crls)
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
            selected_crl_metadata.insert(
                selected_crl_metadata.end(), candidate.crl_fingerprint.begin(), candidate.crl_fingerprint.end());
            selected_crl_metadata.insert(
                selected_crl_metadata.end(), candidate.issuer_fingerprint.begin(), candidate.issuer_fingerprint.end());
            append_i64(candidate.this_update);
            append_i64(candidate.next_update);
            for (std::size_t i = 0U; i < sizeof(candidate.crl_number); ++i)
                selected_crl_metadata.push_back(static_cast<std::uint8_t>(candidate.crl_number >> (i * 8U)));
        }
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
        // Return a VerifyOutcome with a non-zero result_code; chain is empty.
        return VerifyOutcome{MapX509Error(verify_err), {}, std::move(selected_crl_metadata)};
    }

    if (input.evidence_mode == score::crypto::VerificationEvidenceMode::kNone)
    {
        return VerifyOutcome{
            static_cast<uint8_t>(::score::crypto::daemon::provider::cert_management::CertVerifyErrorCode::kNone),
            {},
            {}};
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
    return VerifyOutcome{
        static_cast<uint8_t>(::score::crypto::daemon::provider::cert_management::CertVerifyErrorCode::kNone),
        std::move(verified),
        std::move(selected_crl_metadata)};
}

}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler

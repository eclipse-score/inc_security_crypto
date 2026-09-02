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

#include "score/crypto/src/daemon/provider/score_provider/openssl/cert_management/openssl_cert_parser.hpp"

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <array>
#include <ctime>
#include <memory>
#include <string>
#include <vector>

namespace score::crypto::daemon::provider::score_provider::openssl
{
namespace
{
using CertObject = ::score::crypto::daemon::cert_management::CertObject;
using Metadata = ::score::crypto::daemon::cert_management::CertChainMetadata;
using Error = common::DaemonErrorCode;

struct X509Deleter
{
    void operator()(X509* value) const noexcept
    {
        X509_free(value);
    }
};
using X509Ptr = std::unique_ptr<X509, X509Deleter>;

std::string NameToString(X509_NAME* name)
{
    if (name == nullptr)
        return {};
    BIO* raw_bio = BIO_new(BIO_s_mem());
    if (raw_bio == nullptr)
        return {};
    std::unique_ptr<BIO, decltype(&BIO_free)> bio{raw_bio, &BIO_free};
    if (X509_NAME_print_ex(bio.get(), name, 0, XN_FLAG_RFC2253 & ~XN_FLAG_DN_REV) < 0)
        return {};
    char* data = nullptr;
    const long size = BIO_get_mem_data(bio.get(), &data);
    return size > 0 && data != nullptr ? std::string{data, static_cast<std::size_t>(size)} : std::string{};
}

bool Asn1TimeToEpoch(const ASN1_TIME* value, int64_t& result)
{
    if (value == nullptr)
        return false;
    std::tm calendar{};
    if (ASN1_TIME_to_tm(value, &calendar) != 1)
        return false;
    const std::time_t epoch = timegm(&calendar);
    if (epoch == static_cast<std::time_t>(-1))
        return false;
    result = static_cast<int64_t>(epoch);
    return true;
}

template <typename T>
void CopyOpenSslBytes(const T* data, std::size_t size, std::vector<std::uint8_t>& destination)
{
    if (data != nullptr && size != 0U)
    {
        const auto* first = reinterpret_cast<const std::uint8_t*>(data);
        destination.assign(first, first + size);
    }
}

score::crypto::Expected<CertObject::Sptr, Error> BuildObject(X509* certificate,
                                                             const std::uint8_t* bytes,
                                                             std::size_t size,
                                                             score::crypto::FormatType format)
{
    if (certificate == nullptr || bytes == nullptr || size == 0U)
        return score::crypto::make_unexpected(Error::kCertificateParsingFailed);

    Metadata metadata;
    metadata.subject_canonical = NameToString(X509_get_subject_name(certificate));
    metadata.issuer_canonical = NameToString(X509_get_issuer_name(certificate));
    if (metadata.subject_canonical.empty() || metadata.issuer_canonical.empty() ||
        !Asn1TimeToEpoch(X509_get0_notBefore(certificate), metadata.not_before_epoch_s) ||
        !Asn1TimeToEpoch(X509_get0_notAfter(certificate), metadata.not_after_epoch_s))
    {
        return score::crypto::make_unexpected(Error::kCertificateParsingFailed);
    }

    // Extract serial number as uppercase hex string (e.g., "01ABCDEF").
    // (issuer, serial) is the RFC 5280 canonical certificate identifier.
    {
        const ASN1_INTEGER* serial = X509_get_serialNumber(certificate);
        if (serial != nullptr)
        {
            BIGNUM* bn = ASN1_INTEGER_to_BN(serial, nullptr);
            if (bn != nullptr)
            {
                char* hex = BN_bn2hex(bn);
                if (hex != nullptr)
                {
                    metadata.serial_number_hex = hex;
                    OPENSSL_free(hex);
                }
                BN_free(bn);
            }
        }
    }

    ASN1_OCTET_STRING* skid =
        static_cast<ASN1_OCTET_STRING*>(X509_get_ext_d2i(certificate, NID_subject_key_identifier, nullptr, nullptr));
    if (skid != nullptr)
    {
        CopyOpenSslBytes(
            ASN1_STRING_get0_data(skid), static_cast<std::size_t>(ASN1_STRING_length(skid)), metadata.skid);
        ASN1_OCTET_STRING_free(skid);
    }

    auto* akid =
        static_cast<AUTHORITY_KEYID*>(X509_get_ext_d2i(certificate, NID_authority_key_identifier, nullptr, nullptr));
    if (akid != nullptr)
    {
        if (akid->keyid != nullptr)
            CopyOpenSslBytes(ASN1_STRING_get0_data(akid->keyid),
                             static_cast<std::size_t>(ASN1_STRING_length(akid->keyid)),
                             metadata.akid);
        AUTHORITY_KEYID_free(akid);
    }

    unsigned int digest_size = 0U;
    std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
    if (X509_digest(certificate, EVP_sha256(), digest.data(), &digest_size) != 1 || digest_size != SHA256_DIGEST_LENGTH)
    {
        return score::crypto::make_unexpected(Error::kCertificateParsingFailed);
    }
    metadata.fingerprint.assign(digest.begin(), digest.end());

    BASIC_CONSTRAINTS* constraints =
        static_cast<BASIC_CONSTRAINTS*>(X509_get_ext_d2i(certificate, NID_basic_constraints, nullptr, nullptr));
    if (constraints != nullptr)
    {
        metadata.is_ca = constraints->ca != 0;
        BASIC_CONSTRAINTS_free(constraints);
    }

    return std::make_shared<CertObject>(std::move(metadata), std::vector<std::uint8_t>{bytes, bytes + size}, format);
}

X509Ptr ParseX509(const std::uint8_t* bytes, std::size_t size, score::crypto::FormatType format)
{
    if (bytes == nullptr || size == 0U)
        return {nullptr};
    if (format == score::crypto::FormatType::kDer)
    {
        const unsigned char* cursor = bytes;
        return X509Ptr{d2i_X509(nullptr, &cursor, static_cast<long>(size))};
    }
    BIO* raw_bio = BIO_new_mem_buf(bytes, static_cast<int>(size));
    if (raw_bio == nullptr)
        return {nullptr};
    std::unique_ptr<BIO, decltype(&BIO_free)> bio{raw_bio, &BIO_free};
    return X509Ptr{PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)};
}

}  // namespace

score::crypto::Expected<::score::crypto::daemon::cert_management::CertObject::Sptr, common::DaemonErrorCode>
OpenSslCertParser::ParseCertificate(const std::uint8_t* bytes, std::size_t size, score::crypto::FormatType format)
{
    auto certificate = ParseX509(bytes, size, format);
    if (!certificate)
        return score::crypto::make_unexpected(common::DaemonErrorCode::kCertificateParsingFailed);
    return BuildObject(certificate.get(), bytes, size, format);
}

score::crypto::Expected<std::vector<::score::crypto::daemon::cert_management::CertObject::Sptr>,
                        common::DaemonErrorCode>
OpenSslCertParser::ParseCertificates(const std::uint8_t* bytes, std::size_t size, score::crypto::FormatType format)
{
    if (bytes == nullptr || size == 0U)
        return score::crypto::make_unexpected(common::DaemonErrorCode::kCertificateParsingFailed);

    std::vector<CertObject::Sptr> result;

    if (format == score::crypto::FormatType::kPem)
    {
        BIO* raw_bio = BIO_new_mem_buf(bytes, static_cast<int>(size));
        if (raw_bio == nullptr)
            return score::crypto::make_unexpected(common::DaemonErrorCode::kCertificateParsingFailed);
        std::unique_ptr<BIO, decltype(&BIO_free)> bio{raw_bio, &BIO_free};

        while (true)
        {
            X509Ptr cert{PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)};
            if (!cert)
            {
                // PEM_R_NO_START_LINE signals no more PEM headers — clean EOF, not a parse error
                const unsigned long err = ERR_peek_last_error();
                ERR_clear_error();
                if (ERR_GET_REASON(err) == PEM_R_NO_START_LINE)
                    break;
                return score::crypto::make_unexpected(common::DaemonErrorCode::kCertificateParsingFailed);
            }
            // Re-serialize each cert to DER so BuildObject stores per-cert bytes, not the full bundle
            unsigned char* der_buf = nullptr;
            const int der_len = i2d_X509(cert.get(), &der_buf);
            if (der_len <= 0 || der_buf == nullptr)
                return score::crypto::make_unexpected(common::DaemonErrorCode::kCertificateParsingFailed);
            auto obj =
                BuildObject(cert.get(), der_buf, static_cast<std::size_t>(der_len), score::crypto::FormatType::kDer);
            OPENSSL_free(der_buf);
            if (!obj)
                return score::crypto::make_unexpected(obj.error());
            result.push_back(*obj);
        }
    }
    else
    {
        // DER: loop advancing cursor per certificate until the buffer is consumed
        const unsigned char* cursor = bytes;
        const unsigned char* const end = bytes + size;
        while (cursor < end)
        {
            const unsigned char* const start = cursor;
            X509Ptr cert{d2i_X509(nullptr, &cursor, static_cast<long>(end - cursor))};
            if (!cert)
                return score::crypto::make_unexpected(common::DaemonErrorCode::kCertificateParsingFailed);
            auto obj = BuildObject(
                cert.get(), start, static_cast<std::size_t>(cursor - start), score::crypto::FormatType::kDer);
            if (!obj)
                return score::crypto::make_unexpected(obj.error());
            result.push_back(*obj);
        }
    }

    if (result.empty())
        return score::crypto::make_unexpected(common::DaemonErrorCode::kCertificateParsingFailed);
    return result;
}

// ---------------------------------------------------------------------------
// CRL validation
// ---------------------------------------------------------------------------

namespace
{
struct X509CrlDeleter
{
    void operator()(X509_CRL* p) const noexcept
    {
        X509_CRL_free(p);
    }
};
using X509CrlPtr = std::unique_ptr<X509_CRL, X509CrlDeleter>;

// Parse raw CRL bytes (DER or PEM) into an OpenSSL CRL object.
X509CrlPtr ParseCrlBytes(const std::uint8_t* data, std::size_t size, score::crypto::FormatType format)
{
    if (format == score::crypto::FormatType::kDer)
    {
        const uint8_t* ptr = data;
        return X509CrlPtr(d2i_X509_CRL(nullptr, &ptr, static_cast<long>(size)));
    }
    auto* bio_raw = BIO_new_mem_buf(data, static_cast<int>(size));
    if (!bio_raw)
        return nullptr;
    std::unique_ptr<BIO, decltype(&BIO_free)> bio{bio_raw, &BIO_free};
    return X509CrlPtr(PEM_read_bio_X509_CRL(bio.get(), nullptr, nullptr, nullptr));
}

// Convert an ASN1_TIME to a Unix epoch (seconds). Returns 0 if unavailable.
std::int64_t Asn1TimeToEpoch(const ASN1_TIME* asn1)
{
    if (!asn1)
        return 0;
    struct tm t{};
    if (ASN1_TIME_to_tm(asn1, &t) != 1)
        return 0;

    return static_cast<std::int64_t>(timegm(&t));
}
}  // namespace

score::crypto::Expected<std::int64_t, common::DaemonErrorCode> OpenSslCertParser::ValidateCrl(
    const std::uint8_t* crl_data,
    std::size_t crl_size,
    score::crypto::FormatType crl_format,
    const std::uint8_t* issuer_cert_data,
    std::size_t issuer_cert_size,
    score::crypto::FormatType issuer_cert_format)
{
    if (!crl_data || crl_size == 0U || !issuer_cert_data || issuer_cert_size == 0U)
        return score::crypto::make_unexpected(Error::kInvalidArgument);

    // 1. Parse the CRL.
    X509CrlPtr crl = ParseCrlBytes(crl_data, crl_size, crl_format);
    if (!crl)
    {
        ERR_clear_error();
        return score::crypto::make_unexpected(Error::kCertificateParsingFailed);
    }

    // 2. Parse the issuer certificate.
    X509Ptr issuer_x509;
    if (issuer_cert_format == score::crypto::FormatType::kDer)
    {
        const uint8_t* ptr = issuer_cert_data;
        issuer_x509.reset(d2i_X509(nullptr, &ptr, static_cast<long>(issuer_cert_size)));
    }
    else
    {
        auto* bio_raw = BIO_new_mem_buf(issuer_cert_data, static_cast<int>(issuer_cert_size));
        if (bio_raw)
        {
            std::unique_ptr<BIO, decltype(&BIO_free)> bio{bio_raw, &BIO_free};
            issuer_x509.reset(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
        }
    }
    if (!issuer_x509)
    {
        ERR_clear_error();
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }

    // 3. Verify CRL issuer DN matches the certificate's subject DN.
    if (X509_NAME_cmp(X509_CRL_get_issuer(crl.get()), X509_get_subject_name(issuer_x509.get())) != 0)
        return score::crypto::make_unexpected(Error::kInvalidArgument);

    // 4. Verify the CRL signature using the issuer certificate's public key.
    EVP_PKEY* pkey = X509_get0_pubkey(issuer_x509.get());
    if (!pkey)
        return score::crypto::make_unexpected(Error::kInternalError);
    if (X509_CRL_verify(crl.get(), pkey) != 1)
    {
        ERR_clear_error();
        return score::crypto::make_unexpected(Error::kOperationFailed);
    }

    // 5. Extract nextUpdate (optional field — 0 when absent).
    return Asn1TimeToEpoch(X509_CRL_get0_nextUpdate(crl.get()));
}

}  // namespace score::crypto::daemon::provider::score_provider::openssl

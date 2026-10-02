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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_DETAIL_OPENSSL_CERT_UTILS_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_DETAIL_OPENSSL_CERT_UTILS_HPP

#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/api/types/common.hpp"

#include <openssl/x509.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>

namespace score::crypto::daemon::provider::openssl::detail
{

struct X509Deleter
{
    void operator()(X509* p) const noexcept
    {
        X509_free(p);
    }
};
using UniqueX509 = std::unique_ptr<X509, X509Deleter>;

struct X509CrlDeleter
{
    void operator()(X509_CRL* p) const noexcept
    {
        X509_CRL_free(p);
    }
};
using UniqueX509Crl = std::unique_ptr<X509_CRL, X509CrlDeleter>;

using Sha256Digest = std::array<std::uint8_t, score::crypto::kSha256FingerprintSize>;

/// @brief Parses a single DER or PEM encoded certificate.
///
/// @param bytes Encoded certificate; may be null.
/// @param size Number of bytes at @p bytes.
/// @param format Encoding of the data; any value other than DER is read as PEM.
/// @return The parsed certificate, or nullptr if the input is empty or cannot be parsed.
UniqueX509 ParseX509(const std::uint8_t* bytes, std::size_t size, score::crypto::FormatType format);

/// @brief Parses a single DER or PEM encoded CRL.
///
/// @param bytes Encoded CRL; may be null.
/// @param size Number of bytes at @p bytes.
/// @param format Encoding of the data; any value other than DER is read as PEM.
/// @return The parsed CRL, or nullptr if the input is empty or cannot be parsed.
UniqueX509Crl ParseX509Crl(const std::uint8_t* bytes, std::size_t size, score::crypto::FormatType format);

/// @brief Computes the SHA-256 digest of a certificate's DER encoding.
///
/// @param certificate Certificate to digest; must not be null.
/// @param output Receives the digest on success.
/// @return True if the digest was computed.
bool ComputeSha256(const X509* certificate, Sha256Digest& output);

/// @brief Computes the SHA-256 digest of a CRL's DER encoding.
///
/// @param crl CRL to digest; must not be null.
/// @param output Receives the digest on success.
/// @return True if the digest was computed.
bool ComputeSha256(const X509_CRL* crl, Sha256Digest& output);

/// @brief Converts an ASN.1 time to seconds since the Unix epoch.
///
/// @param value Time to convert; may be null.
/// @param result Set only on success.
/// @return True if @p value is present and convertible.
bool Asn1TimeToEpoch(const ASN1_TIME* value, std::int64_t& result);

/// @brief Reads the CRL number extension.
///
/// @param crl CRL to inspect; must not be null.
/// @return The CRL number, or 0 if the extension is absent, negative, or does not fit in 64 bits.
std::uint64_t ReadCrlNumber(const X509_CRL* crl);

/// @brief Reads the intrinsic metadata of a CRL.
///
/// Sets fingerprint, this_update, next_update and crl_number. A missing thisUpdate or nextUpdate is reported
/// as 0. issuer_fingerprint is left unchanged because it depends on the issuing certificate.
///
/// @param crl CRL to inspect; must not be null.
/// @param metadata Receives the metadata on success.
/// @return True if the CRL digest was computed.
bool ReadCrlMetadata(const X509_CRL* crl, score::crypto::CrlMetadata& metadata);

}  // namespace score::crypto::daemon::provider::openssl::detail

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_DETAIL_OPENSSL_CERT_UTILS_HPP

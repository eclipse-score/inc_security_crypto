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

#include "score/crypto/src/daemon/provider/score_provider/openssl/detail/openssl_cert_utils.hpp"

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <ctime>
#include <memory>

namespace score::crypto::daemon::provider::openssl::detail
{

namespace
{

using UniqueBio = std::unique_ptr<BIO, decltype(&BIO_free)>;

UniqueBio MakeReadOnlyBio(const std::uint8_t* bytes, std::size_t size)
{
    return UniqueBio{BIO_new_mem_buf(bytes, static_cast<int>(size)), &BIO_free};
}

}  // namespace

UniqueX509 ParseX509(const std::uint8_t* bytes, std::size_t size, score::crypto::FormatType format)
{
    if (bytes == nullptr || size == 0U)
        return nullptr;

    if (format == score::crypto::FormatType::kDer)
    {
        const std::uint8_t* cursor = bytes;
        return UniqueX509{d2i_X509(nullptr, &cursor, static_cast<long>(size))};
    }

    const auto bio = MakeReadOnlyBio(bytes, size);
    if (!bio)
        return nullptr;
    return UniqueX509{PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)};
}

UniqueX509Crl ParseX509Crl(const std::uint8_t* bytes, std::size_t size, score::crypto::FormatType format)
{
    if (bytes == nullptr || size == 0U)
        return nullptr;

    if (format == score::crypto::FormatType::kDer)
    {
        const std::uint8_t* cursor = bytes;
        return UniqueX509Crl{d2i_X509_CRL(nullptr, &cursor, static_cast<long>(size))};
    }

    const auto bio = MakeReadOnlyBio(bytes, size);
    if (!bio)
        return nullptr;
    return UniqueX509Crl{PEM_read_bio_X509_CRL(bio.get(), nullptr, nullptr, nullptr)};
}

bool ComputeSha256(const X509* certificate, Sha256Digest& output)
{
    unsigned int digest_size = 0U;
    return X509_digest(certificate, EVP_sha256(), output.data(), &digest_size) == 1 && digest_size == output.size();
}

bool ComputeSha256(const X509_CRL* crl, Sha256Digest& output)
{
    unsigned int digest_size = 0U;
    return X509_CRL_digest(crl, EVP_sha256(), output.data(), &digest_size) == 1 && digest_size == output.size();
}

bool Asn1TimeToEpoch(const ASN1_TIME* value, std::int64_t& result)
{
    if (value == nullptr)
        return false;
    std::tm calendar{};
    if (ASN1_TIME_to_tm(value, &calendar) != 1)
        return false;
    const std::time_t epoch = timegm(&calendar);
    if (epoch == static_cast<std::time_t>(-1))
        return false;
    result = static_cast<std::int64_t>(epoch);
    return true;
}

std::uint64_t ReadCrlNumber(const X509_CRL* crl)
{
    int critical = 0;
    auto* number = static_cast<ASN1_INTEGER*>(X509_CRL_get_ext_d2i(crl, NID_crl_number, &critical, nullptr));
    if (number == nullptr)
        return 0U;
    const std::unique_ptr<ASN1_INTEGER, decltype(&ASN1_INTEGER_free)> number_guard{number, &ASN1_INTEGER_free};

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

bool ReadCrlMetadata(const X509_CRL* crl, score::crypto::CrlMetadata& metadata)
{
    if (!ComputeSha256(crl, metadata.fingerprint))
        return false;

    metadata.this_update = 0;
    metadata.next_update = 0;
    static_cast<void>(Asn1TimeToEpoch(X509_CRL_get0_lastUpdate(crl), metadata.this_update));
    static_cast<void>(Asn1TimeToEpoch(X509_CRL_get0_nextUpdate(crl), metadata.next_update));
    metadata.crl_number = ReadCrlNumber(crl);
    return true;
}

}  // namespace score::crypto::daemon::provider::openssl::detail

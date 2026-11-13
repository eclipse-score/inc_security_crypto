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

#include "score/crypto/src/daemon/provider/score_provider/openssl/cert_management/openssl_cert_parser.hpp"

#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <ctime>
#include <memory>
#include <optional>
#include <vector>

namespace
{

using score::crypto::daemon::provider::openssl::detail::CertSptr;
using score::crypto::daemon::provider::openssl::detail::SelectCrlsPerIssuer;
using CrlDataSptr = std::shared_ptr<const score::crypto::daemon::cert_management::CrlData>;

struct EvpPkeyDeleter
{
    void operator()(EVP_PKEY* p) const noexcept
    {
        EVP_PKEY_free(p);
    }
};
struct X509Deleter
{
    void operator()(X509* p) const noexcept
    {
        X509_free(p);
    }
};
struct CrlDeleter
{
    void operator()(X509_CRL* p) const noexcept
    {
        X509_CRL_free(p);
    }
};
struct Asn1IntegerDeleter
{
    void operator()(ASN1_INTEGER* p) const noexcept
    {
        ASN1_INTEGER_free(p);
    }
};
struct Asn1TimeDeleter
{
    void operator()(ASN1_TIME* p) const noexcept
    {
        ASN1_TIME_free(p);
    }
};

using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using X509Ptr = std::unique_ptr<X509, X509Deleter>;
using CrlPtr = std::unique_ptr<X509_CRL, CrlDeleter>;
using Asn1IntegerPtr = std::unique_ptr<ASN1_INTEGER, Asn1IntegerDeleter>;
using Asn1TimePtr = std::unique_ptr<ASN1_TIME, Asn1TimeDeleter>;

constexpr std::int64_t kBaseTime{1700000000};
constexpr std::int64_t kOneDay{86400};

EvpPkeyPtr GenerateRsaKey()
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (ctx == nullptr)
    {
        return {};
    }
    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
        EVP_PKEY_keygen(ctx, &raw) <= 0)
    {
        raw = nullptr;
    }
    EVP_PKEY_CTX_free(ctx);
    return EvpPkeyPtr{raw};
}

// Self-signed CA certificate with subject and issuer CN=crl-selection-ca.
X509Ptr MakeCaCert(EVP_PKEY* key)
{
    X509Ptr cert{X509_new()};
    if (!cert)
    {
        return {};
    }
    X509_set_version(cert.get(), 2);  // version 3
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 365L * 24L * 3600L);
    X509_set_pubkey(cert.get(), key);
    X509_NAME* name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(
        name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("crl-selection-ca"), -1, -1, 0);
    X509_set_issuer_name(cert.get(), name);
    X509_sign(cert.get(), key, EVP_sha256());
    return cert;
}

// CRL issued under the CA's name and signed with @p signer. A null @p crl_number omits the
// crlNumber extension, which makes the CRL unnumbered.
CrlPtr MakeCrl(X509* ca_cert, EVP_PKEY* signer, std::int64_t this_update, std::optional<long> crl_number)
{
    CrlPtr crl{X509_CRL_new()};
    if (!crl)
    {
        return {};
    }
    X509_CRL_set_version(crl.get(), 1);  // 1 = CRL v2 in OpenSSL's enum
    X509_CRL_set_issuer_name(crl.get(), X509_get_subject_name(ca_cert));

    Asn1TimePtr last{ASN1_TIME_set(nullptr, static_cast<time_t>(this_update))};
    Asn1TimePtr next{ASN1_TIME_set(nullptr, static_cast<time_t>(this_update + kOneDay))};
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    X509_CRL_set1_lastUpdate(crl.get(), last.get());
    X509_CRL_set1_nextUpdate(crl.get(), next.get());
#else
    X509_CRL_set_lastUpdate(crl.get(), last.get());
    X509_CRL_set_nextUpdate(crl.get(), next.get());
#endif

    if (crl_number.has_value())
    {
        Asn1IntegerPtr number{ASN1_INTEGER_new()};
        ASN1_INTEGER_set(number.get(), *crl_number);
        X509_CRL_add1_ext_i2d(crl.get(), NID_crl_number, number.get(), 0, 0);
    }

    X509_CRL_sign(crl.get(), signer, EVP_sha256());
    return crl;
}

std::vector<uint8_t> CrlToDer(X509_CRL* crl)
{
    uint8_t* buf = nullptr;
    const int len = i2d_X509_CRL(crl, &buf);
    if (len <= 0)
    {
        return {};
    }
    std::vector<uint8_t> out(buf, buf + len);
    OPENSSL_free(buf);
    return out;
}

std::vector<uint8_t> X509ToDer(X509* cert)
{
    uint8_t* buf = nullptr;
    const int len = i2d_X509(cert, &buf);
    if (len <= 0)
    {
        return {};
    }
    std::vector<uint8_t> out(buf, buf + len);
    OPENSSL_free(buf);
    return out;
}

CrlDataSptr MakeDerCrlData(const std::vector<uint8_t>& bytes)
{
    auto data = std::make_shared<score::crypto::daemon::cert_management::CrlData>();
    data->bytes = bytes;
    data->format = score::crypto::FormatType::kDer;
    return data;
}

CrlDataSptr MakeDerCrlData(X509_CRL* crl)
{
    return MakeDerCrlData(CrlToDer(crl));
}

}  // namespace

class OpenSslCrlSelectionTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        ca_key_ = GenerateRsaKey();
        other_key_ = GenerateRsaKey();
        ca_cert_ = MakeCaCert(ca_key_.get());
        ASSERT_NE(ca_key_.get(), nullptr);
        ASSERT_NE(other_key_.get(), nullptr);
        ASSERT_NE(ca_cert_.get(), nullptr);

        score::crypto::daemon::provider::score_provider::openssl::OpenSslCertParser parser{
            score::crypto::daemon::common::ProviderId{1U}};
        const auto der = X509ToDer(ca_cert_.get());
        const auto parsed = parser.ParseCertificate(der.data(), der.size(), score::crypto::FormatType::kDer);
        ASSERT_TRUE(parsed.has_value());
        candidates_ = {*parsed};
    }

    EvpPkeyPtr ca_key_;
    EvpPkeyPtr other_key_;
    X509Ptr ca_cert_;
    std::vector<CertSptr> candidates_;
};

TEST_F(OpenSslCrlSelectionTest, EmptyInputGivesEmptySelection)
{
    const auto selected = SelectCrlsPerIssuer({}, candidates_);

    ASSERT_TRUE(selected.has_value());
    EXPECT_TRUE(selected->empty());
}

TEST_F(OpenSslCrlSelectionTest, HigherCrlNumberWinsOverNewerThisUpdate)
{
    const auto newer_but_lower = MakeCrl(ca_cert_.get(), ca_key_.get(), kBaseTime + 1000, 1L);
    const auto older_but_higher = MakeCrl(ca_cert_.get(), ca_key_.get(), kBaseTime, 2L);
    const std::vector<CrlDataSptr> crls{MakeDerCrlData(newer_but_lower.get()), MakeDerCrlData(older_but_higher.get())};

    const auto selected = SelectCrlsPerIssuer(crls, candidates_);

    ASSERT_TRUE(selected.has_value());
    ASSERT_EQ(selected->size(), 1U);
    EXPECT_EQ((*selected)[0].metadata.crl_number, 2U);
    EXPECT_EQ((*selected)[0].metadata.this_update, kBaseTime);
}

TEST_F(OpenSslCrlSelectionTest, NumberedCrlBeatsUnnumberedCrl)
{
    const auto unnumbered = MakeCrl(ca_cert_.get(), ca_key_.get(), kBaseTime + 1000, std::nullopt);
    const auto numbered = MakeCrl(ca_cert_.get(), ca_key_.get(), kBaseTime, 1L);
    const std::vector<CrlDataSptr> crls{MakeDerCrlData(unnumbered.get()), MakeDerCrlData(numbered.get())};

    const auto selected = SelectCrlsPerIssuer(crls, candidates_);

    ASSERT_TRUE(selected.has_value());
    ASSERT_EQ(selected->size(), 1U);
    EXPECT_EQ((*selected)[0].metadata.crl_number, 1U);
}

TEST_F(OpenSslCrlSelectionTest, EqualCrlNumberLatestThisUpdateWins)
{
    const auto earlier = MakeCrl(ca_cert_.get(), ca_key_.get(), kBaseTime, 7L);
    const auto later = MakeCrl(ca_cert_.get(), ca_key_.get(), kBaseTime + 60, 7L);
    const std::vector<CrlDataSptr> crls{MakeDerCrlData(earlier.get()), MakeDerCrlData(later.get())};

    const auto selected = SelectCrlsPerIssuer(crls, candidates_);

    ASSERT_TRUE(selected.has_value());
    ASSERT_EQ(selected->size(), 1U);
    EXPECT_EQ((*selected)[0].metadata.crl_number, 7U);
    EXPECT_EQ((*selected)[0].metadata.this_update, kBaseTime + 60);
}

// The name matches the CA, but the signature does not verify under the CA key.
TEST_F(OpenSslCrlSelectionTest, CrlNotSignedByCandidateIsSkipped)
{
    const auto forged = MakeCrl(ca_cert_.get(), other_key_.get(), kBaseTime, 9L);
    const auto valid = MakeCrl(ca_cert_.get(), ca_key_.get(), kBaseTime, 1L);
    const std::vector<CrlDataSptr> crls{MakeDerCrlData(forged.get()), MakeDerCrlData(valid.get())};

    const auto selected = SelectCrlsPerIssuer(crls, candidates_);

    ASSERT_TRUE(selected.has_value());
    ASSERT_EQ(selected->size(), 1U);
    EXPECT_EQ((*selected)[0].metadata.crl_number, 1U);
}

TEST_F(OpenSslCrlSelectionTest, UnparseableCrlIsSkipped)
{
    const auto valid = MakeCrl(ca_cert_.get(), ca_key_.get(), kBaseTime, 1L);
    const std::vector<CrlDataSptr> crls{MakeDerCrlData(std::vector<uint8_t>{0x30, 0x03, 0x01, 0x01, 0x00}),
                                        MakeDerCrlData(valid.get())};

    const auto selected = SelectCrlsPerIssuer(crls, candidates_);

    ASSERT_TRUE(selected.has_value());
    ASSERT_EQ(selected->size(), 1U);
    EXPECT_EQ((*selected)[0].metadata.crl_number, 1U);
}

// Metadata supplied with the CRL must describe the CRL bytes; a zeroed fingerprint does not.
TEST_F(OpenSslCrlSelectionTest, CrlWithMismatchedMetadataIsSkipped)
{
    const auto valid = MakeCrl(ca_cert_.get(), ca_key_.get(), kBaseTime, 1L);
    auto data = std::make_shared<score::crypto::daemon::cert_management::CrlData>();
    data->bytes = CrlToDer(valid.get());
    data->format = score::crypto::FormatType::kDer;
    data->metadata = score::crypto::CrlMetadata{};

    const auto selected = SelectCrlsPerIssuer({data}, candidates_);

    ASSERT_TRUE(selected.has_value());
    EXPECT_TRUE(selected->empty());
}

// Metadata reported by a first selection, when re-supplied with the same bytes, is accepted.
TEST_F(OpenSslCrlSelectionTest, CrlWithMatchingMetadataIsAccepted)
{
    const auto valid = MakeCrl(ca_cert_.get(), ca_key_.get(), kBaseTime, 1L);
    const std::vector<uint8_t> der = CrlToDer(valid.get());
    const auto first = SelectCrlsPerIssuer({MakeDerCrlData(der)}, candidates_);
    ASSERT_TRUE(first.has_value());
    ASSERT_EQ(first->size(), 1U);

    auto data = std::make_shared<score::crypto::daemon::cert_management::CrlData>();
    data->bytes = der;
    data->format = score::crypto::FormatType::kDer;
    data->metadata = (*first)[0].metadata;

    const auto second = SelectCrlsPerIssuer({data}, candidates_);

    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(second->size(), 1U);
}

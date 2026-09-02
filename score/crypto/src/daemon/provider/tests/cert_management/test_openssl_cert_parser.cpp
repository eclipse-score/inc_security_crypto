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

#include <gtest/gtest.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <cstdint>
#include <ctime>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace
{
using score::crypto::FormatType;
using score::crypto::daemon::common::DaemonErrorCode;
using score::crypto::daemon::common::ProviderId;
using score::crypto::daemon::provider::score_provider::openssl::OpenSslCertParser;

// ---------------------------------------------------------------------------
// ParseCertificate / ParseCertificates tests
// ---------------------------------------------------------------------------

std::string ReadCertificateVector()
{
    std::ifstream input{"score/tests/test_vectors/certificate/basic/certificate.pem"};
    return {std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
}

TEST(OpenSslCertParserTest, ParsesPemCertificateAndExtractsMetadata)
{
    const auto pem = ReadCertificateVector();
    ASSERT_FALSE(pem.empty());
    OpenSslCertParser parser{ProviderId{1U}};
    const auto result =
        parser.ParseCertificate(reinterpret_cast<const std::uint8_t*>(pem.data()), pem.size(), FormatType::kPem);

    ASSERT_TRUE(result.has_value());
    ASSERT_NE(*result, nullptr);
    EXPECT_EQ((*result)->GetFormat(), FormatType::kPem);
    EXPECT_EQ((*result)->GetSubject(), "CN=cert-management-test,O=Eclipse");
    EXPECT_EQ((*result)->GetIssuer(), "CN=cert-management-test,O=Eclipse");
    EXPECT_TRUE((*result)->IsCA());
    EXPECT_EQ((*result)->GetSkid().size(), 20U);
    EXPECT_EQ((*result)->GetFingerprint().size(), 32U);
    EXPECT_EQ((*result)->GetRawBytes().size(), pem.size());
}

TEST(OpenSslCertParserTest, ParsesPemBundleIntoSeparateCertificateObjects)
{
    const auto pem = ReadCertificateVector();
    ASSERT_FALSE(pem.empty());
    const auto bundle = pem + pem;
    OpenSslCertParser parser{ProviderId{1U}};
    const auto result =
        parser.ParseCertificates(reinterpret_cast<const std::uint8_t*>(bundle.data()), bundle.size(), FormatType::kPem);

    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->size(), 2U);
    EXPECT_EQ((*result)[0]->GetFormat(), FormatType::kDer);
    EXPECT_EQ((*result)[1]->GetFormat(), FormatType::kDer);
    EXPECT_TRUE(std::equal((*result)[0]->GetFingerprint().begin(),
                           (*result)[0]->GetFingerprint().end(),
                           (*result)[1]->GetFingerprint().begin(),
                           (*result)[1]->GetFingerprint().end()));
}

TEST(OpenSslCertParserTest, RejectsMalformedCertificate)
{
    constexpr std::string_view malformed{"not a certificate"};
    OpenSslCertParser parser{ProviderId{1U}};
    const auto result = parser.ParseCertificate(
        reinterpret_cast<const std::uint8_t*>(malformed.data()), malformed.size(), FormatType::kPem);

    EXPECT_FALSE(result.has_value());
}

// ---------------------------------------------------------------------------
// ValidateCrl tests
//
// The fixture generates two independent self-signed CA + CRL bundles in-memory
// using the OpenSSL C API so that tests are fully hermetic — no committed
// private keys are required.
//
// CaA  — positive tests: valid CRL signed by CaA, CaA cert as issuer.
// CaB  — issuer-mismatch tests: CaA CRL presented with CaB cert as issuer.
//
// Test coverage:
//   - DER CRL + DER issuer cert                  → success, epoch > 0
//   - PEM CRL + PEM issuer cert                  → success, epoch > 0
//   - DER CRL + PEM issuer cert (cross-format)   → success
//   - PEM CRL + DER issuer cert (cross-format)   → success
//   - nextUpdate epoch is strictly in the future  → epoch > now
//   - DER and PEM paths return identical epoch    → consistency
//   - Issuer DN mismatch (CaA CRL + CaB cert)    → kInvalidArgument
//   - Tampered CRL signature (byte flip in sig)  → kOperationFailed
//   - Malformed CRL bytes                         → kCertificateParsingFailed
//   - Malformed issuer cert bytes                 → kInvalidArgument
//   - Null CRL data pointer                       → kInvalidArgument
//   - Zero CRL size                               → kInvalidArgument
//   - Null issuer cert data pointer               → kInvalidArgument
//   - Zero issuer cert size                       → kInvalidArgument
// ---------------------------------------------------------------------------

// RAII wrappers for OpenSSL objects used exclusively in this test file.
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
struct BioDeleter
{
    void operator()(BIO* p) const noexcept
    {
        BIO_free(p);
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
using BioPtr = std::unique_ptr<BIO, BioDeleter>;
using Asn1TimePtr = std::unique_ptr<ASN1_TIME, Asn1TimeDeleter>;

// Generate a 2048-bit RSA key pair.
EvpPkeyPtr GenerateRsaKey()
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx)
        return {};
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY* raw = nullptr;
    EVP_PKEY_keygen(ctx, &raw);
    EVP_PKEY_CTX_free(ctx);
    return EvpPkeyPtr{raw};
}

// Build a minimal self-signed CA certificate. Subject/issuer = CN=<cn>,O=Eclipse.
X509Ptr MakeSelfSignedCert(EVP_PKEY* pkey, const char* cn)
{
    X509Ptr cert{X509_new()};
    if (!cert)
        return {};
    X509_set_version(cert.get(), 2);  // version 3
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 365L * 24L * 3600L);
    X509_set_pubkey(cert.get(), pkey);
    X509_NAME* name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(cn), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("Eclipse"), -1, -1, 0);
    X509_set_issuer_name(cert.get(), name);
    X509_sign(cert.get(), pkey, EVP_sha256());
    return cert;
}

// Build and sign an empty CRL (no revoked entries, nextUpdate = now + 365 days).
CrlPtr MakeSignedCrl(X509* issuer, EVP_PKEY* issuer_key)
{
    CrlPtr crl{X509_CRL_new()};
    if (!crl)
        return {};
    X509_CRL_set_version(crl.get(), 1);  // 1 = CRL v2 in OpenSSL's enum
    X509_CRL_set_issuer_name(crl.get(), X509_get_subject_name(issuer));
    {
        Asn1TimePtr last{ASN1_TIME_new()};
        X509_gmtime_adj(last.get(), 0);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        X509_CRL_set1_lastUpdate(crl.get(), last.get());
#else
        X509_CRL_set_lastUpdate(crl.get(), last.get());
#endif
    }
    {
        Asn1TimePtr next{ASN1_TIME_new()};
        X509_gmtime_adj(next.get(), 365L * 24L * 3600L);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        X509_CRL_set1_nextUpdate(crl.get(), next.get());
#else
        X509_CRL_set_nextUpdate(crl.get(), next.get());
#endif
    }
    X509_CRL_sign(crl.get(), issuer_key, EVP_sha256());
    return crl;
}

// Serialise an X509 certificate to raw DER bytes.
std::vector<uint8_t> X509ToDer(X509* cert)
{
    uint8_t* buf = nullptr;
    const int len = i2d_X509(cert, &buf);
    if (len <= 0)
        return {};
    std::vector<uint8_t> out(buf, buf + len);
    OPENSSL_free(buf);
    return out;
}

// Serialise an X509 certificate to PEM bytes.
std::vector<uint8_t> X509ToPem(X509* cert)
{
    BioPtr bio{BIO_new(BIO_s_mem())};
    PEM_write_bio_X509(bio.get(), cert);
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio.get(), &data);
    return {reinterpret_cast<const uint8_t*>(data), reinterpret_cast<const uint8_t*>(data) + len};
}

// Serialise an X509_CRL to raw DER bytes.
std::vector<uint8_t> CrlToDer(X509_CRL* crl)
{
    uint8_t* buf = nullptr;
    const int len = i2d_X509_CRL(crl, &buf);
    if (len <= 0)
        return {};
    std::vector<uint8_t> out(buf, buf + len);
    OPENSSL_free(buf);
    return out;
}

// Serialise an X509_CRL to PEM bytes.
std::vector<uint8_t> CrlToPem(X509_CRL* crl)
{
    BioPtr bio{BIO_new(BIO_s_mem())};
    PEM_write_bio_X509_CRL(bio.get(), crl);
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio.get(), &data);
    return {reinterpret_cast<const uint8_t*>(data), reinterpret_cast<const uint8_t*>(data) + len};
}

// ---------------------------------------------------------------------------
// Fixture — generates two CA + CRL bundles once for the whole test suite.
// ---------------------------------------------------------------------------

struct CaBundle
{
    std::vector<uint8_t> cert_der;
    std::vector<uint8_t> cert_pem;
    std::vector<uint8_t> crl_der;
    std::vector<uint8_t> crl_pem;
};

class ValidateCrlTest : public ::testing::Test
{
  protected:
    static void SetUpTestSuite()
    {
        // CA A — cert + CRL both generated; used for positive tests.
        {
            auto pkey = GenerateRsaKey();
            ASSERT_TRUE(pkey) << "RSA key generation for CA-A failed";
            auto cert = MakeSelfSignedCert(pkey.get(), "Test-CA-A");
            ASSERT_TRUE(cert) << "Self-signed cert for CA-A failed";
            auto crl = MakeSignedCrl(cert.get(), pkey.get());
            ASSERT_TRUE(crl) << "CRL generation for CA-A failed";
            s_ca_a.cert_der = X509ToDer(cert.get());
            s_ca_a.cert_pem = X509ToPem(cert.get());
            s_ca_a.crl_der = CrlToDer(crl.get());
            s_ca_a.crl_pem = CrlToPem(crl.get());
        }
        // CA B — cert only; its cert is used as the wrong-issuer argument.
        {
            auto pkey = GenerateRsaKey();
            ASSERT_TRUE(pkey) << "RSA key generation for CA-B failed";
            auto cert = MakeSelfSignedCert(pkey.get(), "Test-CA-B");
            ASSERT_TRUE(cert) << "Self-signed cert for CA-B failed";
            s_ca_b.cert_der = X509ToDer(cert.get());
            s_ca_b.cert_pem = X509ToPem(cert.get());
        }
    }

    // Convenience wrapper — calls ValidateCrl with vector data.
    static score::crypto::Expected<std::int64_t, DaemonErrorCode> Validate(const std::vector<uint8_t>& crl,
                                                                           FormatType crl_fmt,
                                                                           const std::vector<uint8_t>& issuer,
                                                                           FormatType issuer_fmt)
    {
        OpenSslCertParser parser{ProviderId{1U}};
        return parser.ValidateCrl(crl.data(), crl.size(), crl_fmt, issuer.data(), issuer.size(), issuer_fmt);
    }

    static CaBundle s_ca_a;
    static CaBundle s_ca_b;
};

CaBundle ValidateCrlTest::s_ca_a;
CaBundle ValidateCrlTest::s_ca_b;

// ---------------------------------------------------------------------------
// Happy-path tests
// ---------------------------------------------------------------------------

TEST_F(ValidateCrlTest, ValidDerCrl_DerIssuer_ReturnsNextUpdateEpoch)
{
    const auto result = Validate(s_ca_a.crl_der, FormatType::kDer, s_ca_a.cert_der, FormatType::kDer);
    ASSERT_TRUE(result.has_value());
    EXPECT_GT(*result, 0);
}

TEST_F(ValidateCrlTest, ValidPemCrl_PemIssuer_ReturnsNextUpdateEpoch)
{
    const auto result = Validate(s_ca_a.crl_pem, FormatType::kPem, s_ca_a.cert_pem, FormatType::kPem);
    ASSERT_TRUE(result.has_value());
    EXPECT_GT(*result, 0);
}

TEST_F(ValidateCrlTest, ValidDerCrl_PemIssuer_CrossFormat_ReturnsNextUpdateEpoch)
{
    const auto result = Validate(s_ca_a.crl_der, FormatType::kDer, s_ca_a.cert_pem, FormatType::kPem);
    ASSERT_TRUE(result.has_value());
    EXPECT_GT(*result, 0);
}

TEST_F(ValidateCrlTest, ValidPemCrl_DerIssuer_CrossFormat_ReturnsNextUpdateEpoch)
{
    const auto result = Validate(s_ca_a.crl_pem, FormatType::kPem, s_ca_a.cert_der, FormatType::kDer);
    ASSERT_TRUE(result.has_value());
    EXPECT_GT(*result, 0);
}

// nextUpdate was set to now + 365 days, so the epoch must be strictly in the future.
TEST_F(ValidateCrlTest, ValidCrl_NextUpdateIsInFuture)
{
    const auto result = Validate(s_ca_a.crl_der, FormatType::kDer, s_ca_a.cert_der, FormatType::kDer);
    ASSERT_TRUE(result.has_value());
    const std::int64_t now_epoch = static_cast<std::int64_t>(std::time(nullptr));
    EXPECT_GT(*result, now_epoch);
}

// DER and PEM paths must decode identically — same nextUpdate epoch.
TEST_F(ValidateCrlTest, ValidCrl_DerAndPemReturnSameEpoch)
{
    const auto der_result = Validate(s_ca_a.crl_der, FormatType::kDer, s_ca_a.cert_der, FormatType::kDer);
    const auto pem_result = Validate(s_ca_a.crl_pem, FormatType::kPem, s_ca_a.cert_pem, FormatType::kPem);
    ASSERT_TRUE(der_result.has_value());
    ASSERT_TRUE(pem_result.has_value());
    EXPECT_EQ(*der_result, *pem_result);
}

// ---------------------------------------------------------------------------
// Negative tests — issuer mismatch and signature failure
// ---------------------------------------------------------------------------

// CRL was signed by CA-A; CA-B cert has a different subject DN (Test-CA-B vs
// Test-CA-A).  The issuer DN check fails before signature verification.
TEST_F(ValidateCrlTest, IssuerDnMismatch_ReturnsInvalidArgument)
{
    const auto result = Validate(s_ca_a.crl_der, FormatType::kDer, s_ca_b.cert_der, FormatType::kDer);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kInvalidArgument);
}

// Flip a byte 16 bytes from the end of the DER — deep inside the 256-byte RSA
// signature — so the issuer DN check passes but X509_CRL_verify() fails.
TEST_F(ValidateCrlTest, TamperedCrlSignature_ReturnsOperationFailed)
{
    ASSERT_GE(s_ca_a.crl_der.size(), 32U);
    auto tampered = s_ca_a.crl_der;
    tampered[tampered.size() - 16U] ^= 0xFFU;
    const auto result = Validate(tampered, FormatType::kDer, s_ca_a.cert_der, FormatType::kDer);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kOperationFailed);
}

// ---------------------------------------------------------------------------
// Negative tests — parse failures
// ---------------------------------------------------------------------------

TEST_F(ValidateCrlTest, MalformedCrlBytes_ReturnsCertificateParsingFailed)
{
    const std::vector<uint8_t> garbage{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
    const auto result = Validate(garbage, FormatType::kDer, s_ca_a.cert_der, FormatType::kDer);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kCertificateParsingFailed);
}

TEST_F(ValidateCrlTest, MalformedIssuerCertBytes_ReturnsInvalidArgument)
{
    const std::vector<uint8_t> garbage{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
    const auto result = Validate(s_ca_a.crl_der, FormatType::kDer, garbage, FormatType::kDer);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kInvalidArgument);
}

// ---------------------------------------------------------------------------
// Negative tests — null / zero-size inputs
// ---------------------------------------------------------------------------

TEST_F(ValidateCrlTest, NullCrlData_ReturnsInvalidArgument)
{
    OpenSslCertParser parser{ProviderId{1U}};
    const auto result = parser.ValidateCrl(nullptr,
                                           s_ca_a.crl_der.size(),
                                           FormatType::kDer,
                                           s_ca_a.cert_der.data(),
                                           s_ca_a.cert_der.size(),
                                           FormatType::kDer);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kInvalidArgument);
}

TEST_F(ValidateCrlTest, ZeroCrlSize_ReturnsInvalidArgument)
{
    OpenSslCertParser parser{ProviderId{1U}};
    const auto result = parser.ValidateCrl(
        s_ca_a.crl_der.data(), 0U, FormatType::kDer, s_ca_a.cert_der.data(), s_ca_a.cert_der.size(), FormatType::kDer);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kInvalidArgument);
}

TEST_F(ValidateCrlTest, NullIssuerCertData_ReturnsInvalidArgument)
{
    OpenSslCertParser parser{ProviderId{1U}};
    const auto result = parser.ValidateCrl(s_ca_a.crl_der.data(),
                                           s_ca_a.crl_der.size(),
                                           FormatType::kDer,
                                           nullptr,
                                           s_ca_a.cert_der.size(),
                                           FormatType::kDer);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kInvalidArgument);
}

TEST_F(ValidateCrlTest, ZeroIssuerCertSize_ReturnsInvalidArgument)
{
    OpenSslCertParser parser{ProviderId{1U}};
    const auto result = parser.ValidateCrl(
        s_ca_a.crl_der.data(), s_ca_a.crl_der.size(), FormatType::kDer, s_ca_a.cert_der.data(), 0U, FormatType::kDer);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kInvalidArgument);
}

}  // namespace

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

#include "score/crypto/src/api/csr/csr_request.hpp"
#include "score/crypto/src/common/csr_der.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/csr_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/csr/csr_processing.hpp"
#include <gtest/gtest.h>
#include <openssl/x509v3.h>
#include <algorithm>
#include <array>
#include <memory>

namespace score::crypto
{
namespace
{
namespace limits = daemon::provider::handler::csr_handler_operations;
NativeCsrProcessing processing;  // Explicit daemon-only test adapter; no production fallback.

TEST(CsrRequestTest, EncodesSubjectAndAttributesWithoutKeyMaterial)
{
    CsrRequest request;
    ASSERT_TRUE(request.subject.Add(processing, CsrOid::kCommonName, "device\"\\\n\té").has_value());
    ASSERT_TRUE(request.subject.Add(processing, CsrOid::kOrganization, "organization").has_value());
    ASSERT_TRUE(request.subject.Add(processing, CsrOid::kOrganizationalUnit, "first").has_value());
    ASSERT_TRUE(request.subject.Add(processing, CsrOid::kOrganizationalUnit, "second").has_value());
    auto usage = CsrExtension::KeyUsage(processing, {CsrKeyUsage::kDigitalSignature});
    ASSERT_TRUE(usage.has_value());
    request.extensions.push_back(usage.value());
    request.challenge_password = "secret\"\\\n";
    auto encoded = request.ToDer(processing);
    ASSERT_TRUE(encoded.has_value());
    EXPECT_TRUE(csr::der::IsCanonicalDer(encoded.value()));
    std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)> decoded{X509_REQ_new(), X509_REQ_free};
    ASSERT_TRUE(decoded);
    ASSERT_TRUE(csr::der::PopulateRequest(decoded.get(), encoded.value()).has_value());
    EXPECT_EQ(X509_REQ_get0_pubkey(decoded.get()), nullptr);
    auto* subject = X509_REQ_get_subject_name(decoded.get());
    ASSERT_EQ(X509_NAME_entry_count(subject), 4);
    const std::array<std::string, 4> values{"device\"\\\n\té", "organization", "first", "second"};
    const std::array<int, 4> identifiers{
        NID_commonName, NID_organizationName, NID_organizationalUnitName, NID_organizationalUnitName};
    for (int i = 0; i < 4; ++i)
    {
        auto* entry = X509_NAME_get_entry(subject, i);
        EXPECT_EQ(X509_NAME_ENTRY_set(entry), i);
        EXPECT_EQ(OBJ_obj2nid(X509_NAME_ENTRY_get_object(entry)), identifiers[static_cast<std::size_t>(i)]);
        const auto* value = X509_NAME_ENTRY_get_data(entry);
        EXPECT_EQ(std::string(reinterpret_cast<const char*>(ASN1_STRING_get0_data(value)),
                              static_cast<std::size_t>(ASN1_STRING_length(value))),
                  values[static_cast<std::size_t>(i)]);
    }
    ASSERT_EQ(X509_REQ_get_attr_count(decoded.get()), 2);
    const int password_index = X509_REQ_get_attr_by_NID(decoded.get(), NID_pkcs9_challengePassword, -1);
    ASSERT_GE(password_index, 0);
    const auto* password = X509_ATTRIBUTE_get0_type(X509_REQ_get_attr(decoded.get(), password_index), 0);
    ASSERT_NE(password, nullptr);
    EXPECT_EQ(std::string(reinterpret_cast<const char*>(ASN1_STRING_get0_data(password->value.asn1_string)),
                          static_cast<std::size_t>(ASN1_STRING_length(password->value.asn1_string))),
              request.challenge_password);
    auto* extensions = X509_REQ_get_extensions(decoded.get());
    ASSERT_NE(extensions, nullptr);
    ASSERT_EQ(sk_X509_EXTENSION_num(extensions), 1);
    EXPECT_EQ(OBJ_obj2nid(X509_EXTENSION_get_object(sk_X509_EXTENSION_value(extensions, 0))), NID_key_usage);
    EXPECT_EQ(X509_EXTENSION_get_critical(sk_X509_EXTENSION_value(extensions, 0)), 1);
    sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
}

TEST(CsrRequestTest, SupportsEveryTypedOidAndCustomAttributes)
{
    CsrSubject subject;
    for (unsigned i = 0; i <= static_cast<unsigned>(CsrOid::kOrganizationIdentifier); ++i)
    {
        EXPECT_TRUE(subject.Add(processing, static_cast<CsrOid>(i), "value").has_value()) << i;
    }
    EXPECT_TRUE(subject.Add(processing, "1.2.3.4.5", "custom").has_value());
    EXPECT_FALSE(subject.Add(processing, static_cast<CsrOid>(999), "value").has_value());
    for (const auto* oid : {"CN", "", "3.1", "1.40", "1.02.3", "1.2.", "1..2", "1.2.x", "0.99.1"})
    {
        EXPECT_FALSE(subject.Add(processing, oid, "value").has_value()) << oid;
    }
    EXPECT_TRUE(subject.Add(processing, "2.999.123456789012345678901234567890", "value").has_value());
}

TEST(CsrRequestTest, ParsesEscapedCompatibilityDnAndRejectsAmbiguousSyntax)
{
    auto subject = CsrSubject::FromDn(processing, "CN=device\\,one\\=two\\\\three,O=organization,C=DE");
    ASSERT_TRUE(subject.has_value());
    ASSERT_EQ(subject->Attributes().size(), 3U);
    EXPECT_EQ(subject->Attributes()[0].value, "device,one=two\\three");
    for (const auto* dn : {"", "CN=", "CN=x,", "CN=x+OU=y", "CN=\\23", "CN=x\\", "CN=x=bad", "unknown=x"})
    {
        EXPECT_FALSE(CsrSubject::FromDn(processing, dn).has_value()) << dn;
    }
}

TEST(CsrRequestTest, RejectsInvalidUtf8NulAndExcessiveBoundsWithoutMutation)
{
    CsrSubject subject;
    EXPECT_FALSE(subject.Add(processing, CsrOid::kCommonName, std::string{"a\0b", 3U}).has_value());
    for (const auto& text : {std::string{"\xC0\x80"},
                             std::string{"\xED\xA0\x80"},
                             std::string{"\xF4\x90\x80\x80"},
                             std::string{"\xE2\x82"},
                             std::string{"\x80"}})
    {
        EXPECT_FALSE(subject.Add(processing, CsrOid::kCommonName, text).has_value());
    }
    EXPECT_FALSE(
        subject.Add(processing, CsrOid::kCommonName, std::string(limits::kMaxValueBytes + 1U, 'x')).has_value());
    EXPECT_TRUE(subject.Attributes().empty());
    for (std::size_t i = 0; i < limits::kMaxSubjectEntries; ++i)
    {
        ASSERT_TRUE(subject.Add(processing, CsrOid::kOrganizationalUnit, "unit").has_value());
    }
    EXPECT_FALSE(subject.Add(processing, CsrOid::kCommonName, "excess").has_value());
    CsrRequest request;
    EXPECT_FALSE(request.Validate(processing).has_value());
    ASSERT_TRUE(request.subject.Add(processing, CsrOid::kCommonName, "device").has_value());
    request.challenge_password.assign(limits::kMaxChallengePasswordBytes + 1U, 'x');
    EXPECT_FALSE(request.Validate(processing).has_value());
    request.challenge_password.clear();
    for (std::size_t i = 0; i < 10U; ++i)
    {
        ASSERT_TRUE(request.subject.Add(processing, CsrOid::kOrganizationalUnit, std::string(2048U, 'x')).has_value());
    }
    EXPECT_FALSE(request.Validate(processing).has_value());
}

TEST(CsrRequestTest, ExtensionHelpersAreTypedBoundedAndInjectionResistant)
{
    auto sans = CsrExtension::SubjectAltNames(processing,
                                              {{CsrSanType::kDns, "device.example"},
                                               {CsrSanType::kIp, "::1"},
                                               {CsrSanType::kEmail, "user@example.com"},
                                               {CsrSanType::kUri, "https://example.com/device"}});
    ASSERT_TRUE(sans.has_value());
    EXPECT_EQ(sans->value, "DNS:device.example,IP:::1,email:user@example.com,URI:https://example.com/device");
    for (const auto* value : {"x,DNS:injected", "@section", "x\nDNS:injected", "x\0y", "", "a b"})
    {
        if (std::string_view{value} == "x")
        {
            continue;
        }
        EXPECT_FALSE(CsrExtension::SubjectAltNames(processing, {{CsrSanType::kDns, value}}).has_value());
    }
    EXPECT_FALSE(CsrExtension::SubjectAltNames(processing, {{CsrSanType::kDns, std::string{"x\0y", 3}}}).has_value());
    EXPECT_FALSE(CsrExtension::KeyUsage(processing, {}).has_value());
    EXPECT_FALSE(CsrExtension::KeyUsage(processing, {CsrKeyUsage::kDigitalSignature, CsrKeyUsage::kDigitalSignature})
                     .has_value());
    EXPECT_FALSE(CsrExtension::KeyUsage(processing, {CsrKeyUsage::kEncipherOnly}).has_value());
    EXPECT_TRUE(
        CsrExtension::KeyUsage(processing, {CsrKeyUsage::kKeyAgreement, CsrKeyUsage::kEncipherOnly}).has_value());
    EXPECT_FALSE(CsrExtension::BasicConstraints(processing, false, 0).has_value());
    auto constraints = CsrExtension::BasicConstraints(processing, true, 2);
    ASSERT_TRUE(constraints.has_value());
    EXPECT_EQ(constraints->value, "CA:TRUE,pathlen:2");
    EXPECT_TRUE(CsrExtension::ExtendedKeyUsage(processing, {"1.3.6.1.5.5.7.3.2"}).has_value());
    EXPECT_FALSE(CsrExtension::ExtendedKeyUsage(processing, {"clientAuth,@section"}).has_value());
    const std::array<uint8_t, 4> der{0x04, 0x02, 0xAB, 0xCD};
    auto custom = CsrExtension::CustomDer(processing, "1.2.3.4", der, true);
    ASSERT_TRUE(custom.has_value());
    EXPECT_EQ(custom->value, "DER:04:02:AB:CD");
    EXPECT_TRUE(custom->critical);
    EXPECT_FALSE(CsrExtension::CustomDer(processing, "1.2.3.4", {}).has_value());
}

TEST(CsrRequestTest, RejectsDuplicateAliasAndInvalidExtensions)
{
    CsrRequest request;
    ASSERT_TRUE(request.subject.Add(processing, CsrOid::kCommonName, "device").has_value());
    request.extensions = {{"2.5.29.15", true, "digitalSignature"}, {"2.5.29.15", false, "keyAgreement"}};
    EXPECT_FALSE(request.Validate(processing).has_value());
    request.extensions = {{"keyUsage", true, "digitalSignature"}};
    EXPECT_FALSE(request.Validate(processing).has_value());
    request.extensions = {{"1.2.3.4", false, ""}};
    EXPECT_FALSE(request.Validate(processing).has_value());
    request.extensions.clear();
    for (std::size_t i = 0; i <= limits::kMaxExtensions; ++i)
    {
        request.extensions.push_back({"1.2.3." + std::to_string(i), false, "DER:05:00"});
    }
    EXPECT_FALSE(request.Validate(processing).has_value());
}

TEST(CsrRequestTest, StructuralValidationAllowsPlaceholdersButEncodingAppliesOpenSslRules)
{
    CsrRequest request;
    ASSERT_TRUE(request.subject.Add(processing, CsrOid::kCountry, "${country}").has_value());
    request.extensions = {{"2.5.29.17", false, "DNS:${hostname}"}};
    EXPECT_TRUE(request.Validate(processing).has_value());
    EXPECT_FALSE(request.ToDer(processing).has_value());
    request.subject = CsrSubject{};
    ASSERT_TRUE(request.subject.Add(processing, CsrOid::kCommonName, "device").has_value());
    request.extensions = {{"2.5.29.15", true, "not-a-key-usage"}};
    EXPECT_TRUE(request.Validate(processing).has_value());
    EXPECT_FALSE(request.ToDer(processing).has_value());
}

TEST(CsrRequestTest, OptionalSpkiSuppliesContextButIsNeverPopulated)
{
    const std::array<unsigned char, 32> raw_key{1U};
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key{
        EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, raw_key.data(), raw_key.size()), EVP_PKEY_free};
    ASSERT_TRUE(key);
    const int length = i2d_PUBKEY(key.get(), nullptr);
    ASSERT_GT(length, 0);
    std::vector<std::uint8_t> spki(static_cast<std::size_t>(length));
    auto* cursor = spki.data();
    ASSERT_EQ(i2d_PUBKEY(key.get(), &cursor), length);
    CsrRequest request;
    ASSERT_TRUE(request.subject.Add(processing, CsrOid::kCommonName, "device").has_value());
    request.extensions = {{"2.5.29.14", false, "hash"}};
    EXPECT_TRUE(request.Validate(processing).has_value());
    EXPECT_FALSE(request.ToDer(processing).has_value());
    auto encoded = request.ToDer(processing, spki);
    ASSERT_TRUE(encoded.has_value());
    std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)> decoded{X509_REQ_new(), X509_REQ_free};
    ASSERT_TRUE(decoded);
    ASSERT_TRUE(csr::der::PopulateRequest(decoded.get(), encoded.value()).has_value());
    EXPECT_EQ(X509_REQ_get0_pubkey(decoded.get()), nullptr);
    auto* extensions = X509_REQ_get_extensions(decoded.get());
    ASSERT_NE(extensions, nullptr);
    ASSERT_EQ(sk_X509_EXTENSION_num(extensions), 1);
    auto* identifier = static_cast<ASN1_OCTET_STRING*>(X509V3_EXT_d2i(sk_X509_EXTENSION_value(extensions, 0)));
    ASSERT_NE(identifier, nullptr);
    EXPECT_EQ(ASN1_STRING_length(identifier), 20);
    ASN1_OCTET_STRING_free(identifier);
    sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
    spki.push_back(0U);
    EXPECT_FALSE(request.ToDer(processing, spki).has_value());
}

TEST(CsrRequestTest, CustomExtensionOctetsRemainOpaqueAndCriticalityOverridesConfig)
{
    CsrRequest request;
    ASSERT_TRUE(request.subject.Add(processing, CsrOid::kCommonName, "device").has_value());
    const std::array<std::uint8_t, 3> opaque{0xFFU, 0U, 0x80U};
    auto extension = CsrExtension::CustomDer(processing, "1.2.3.4", opaque, true);
    ASSERT_TRUE(extension.has_value());
    request.extensions = {extension.value(), {"2.5.29.19", false, "critical,CA:FALSE"}};
    auto encoded = request.ToDer(processing);
    ASSERT_TRUE(encoded.has_value());
    std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)> decoded{X509_REQ_new(), X509_REQ_free};
    ASSERT_TRUE(decoded);
    ASSERT_TRUE(csr::der::PopulateRequest(decoded.get(), encoded.value()).has_value());
    auto* extensions = X509_REQ_get_extensions(decoded.get());
    ASSERT_NE(extensions, nullptr);
    ASSERT_EQ(sk_X509_EXTENSION_num(extensions), 2);
    auto* custom = sk_X509_EXTENSION_value(extensions, 0);
    EXPECT_EQ(X509_EXTENSION_get_critical(custom), 1);
    const auto* octets = X509_EXTENSION_get_data(custom);
    EXPECT_EQ(ASN1_STRING_length(octets), 3);
    EXPECT_TRUE(std::equal(opaque.begin(), opaque.end(), ASN1_STRING_get0_data(octets)));
    EXPECT_EQ(X509_EXTENSION_get_critical(sk_X509_EXTENSION_value(extensions, 1)), 0);
    sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
}
}  // namespace
}  // namespace score::crypto

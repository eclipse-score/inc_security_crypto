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

#include "score/crypto/src/common/csr_der.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/csr_handler_operations.hpp"

#include <gtest/gtest.h>
#include <openssl/asn1t.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <array>
#include <memory>
#include <string>

namespace score::crypto::csr::der
{
namespace
{
namespace bounds = daemon::provider::handler::csr_handler_operations;
using RequestPtr = std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)>;

// Independent test schema lets tests express invalid attributes without using
// the production parameter validator. Encoding still uses OpenSSL templates.
struct EnvelopeFixture
{
    X509_NAME* subject;
    STACK_OF(X509_ATTRIBUTE) * attributes;
};
ASN1_SEQUENCE(EnvelopeFixture) = {ASN1_SIMPLE(EnvelopeFixture, subject, X509_NAME),
                                  ASN1_SET_OF(EnvelopeFixture,
                                              attributes,
                                              X509_ATTRIBUTE)} ASN1_SEQUENCE_END(EnvelopeFixture)
    IMPLEMENT_ASN1_ALLOC_FUNCTIONS(EnvelopeFixture) using FixturePtr =
        std::unique_ptr<EnvelopeFixture, decltype(&EnvelopeFixture_free)>;

FixturePtr Fixture()
{
    FixturePtr fixture{EnvelopeFixture_new(), EnvelopeFixture_free};
    if (fixture)
    {
        const unsigned char value[] = "device";
        if (X509_NAME_add_entry_by_NID(fixture->subject, NID_commonName, MBSTRING_UTF8, value, 6, -1, 0) != 1)
        {
            fixture.reset();
        }
    }
    return fixture;
}

Bytes EncodeFixture(const EnvelopeFixture* fixture)
{
    const auto* item = ASN1_ITEM_rptr(EnvelopeFixture);
    const auto* value = reinterpret_cast<const ASN1_VALUE*>(fixture);
    const int size = ASN1_item_i2d(value, nullptr, item);
    if (size <= 0)
    {
        return {};
    }
    Bytes bytes(static_cast<std::size_t>(size));
    auto* cursor = bytes.data();
    if (ASN1_item_i2d(value, &cursor, item) != size)
    {
        return {};
    }
    return bytes;
}

bool AddAttribute(EnvelopeFixture* fixture, int nid, std::string_view text = "password", int type = MBSTRING_UTF8)
{
    std::unique_ptr<X509_ATTRIBUTE, decltype(&X509_ATTRIBUTE_free)> attribute{
        X509_ATTRIBUTE_create_by_NID(nullptr, nid, type, text.data(), static_cast<int>(text.size())),
        X509_ATTRIBUTE_free};
    if (!attribute || sk_X509_ATTRIBUTE_push(fixture->attributes, attribute.get()) == 0)
    {
        return false;
    }
    static_cast<void>(attribute.release());
    return true;
}

bool AddRequestedExtensions(EnvelopeFixture* fixture, bool duplicate_oid = false, std::size_t count = 1U)
{
    RequestPtr request{X509_REQ_new(), X509_REQ_free};
    if (!request)
    {
        return false;
    }
    auto* extensions = sk_X509_EXTENSION_new_null();
    if (extensions == nullptr)
    {
        return false;
    }
    bool ok = true;
    for (std::size_t i = 0U; i < count; ++i)
    {
        const auto text = "1.2.3." + std::to_string(duplicate_oid ? 0U : i);
        std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)> oid{OBJ_txt2obj(text.c_str(), 1), ASN1_OBJECT_free};
        std::unique_ptr<ASN1_OCTET_STRING, decltype(&ASN1_OCTET_STRING_free)> value{ASN1_OCTET_STRING_new(),
                                                                                    ASN1_OCTET_STRING_free};
        const std::array<unsigned char, 3> opaque{0xFFU, 0U, 0x80U};
        if (!oid || !value || ASN1_OCTET_STRING_set(value.get(), opaque.data(), 3) != 1)
        {
            ok = false;
            break;
        }
        std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> extension{
            X509_EXTENSION_create_by_OBJ(nullptr, oid.get(), 0, value.get()), X509_EXTENSION_free};
        if (!extension || sk_X509_EXTENSION_push(extensions, extension.get()) == 0)
        {
            ok = false;
            break;
        }
        static_cast<void>(extension.release());
    }
    ok = ok && X509_REQ_add_extensions(request.get(), extensions) == 1;
    sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
    if (!ok)
    {
        return false;
    }
    std::unique_ptr<X509_ATTRIBUTE, decltype(&X509_ATTRIBUTE_free)> attribute{
        X509_ATTRIBUTE_dup(X509_REQ_get_attr(request.get(), 0)), X509_ATTRIBUTE_free};
    if (!attribute || sk_X509_ATTRIBUTE_push(fixture->attributes, attribute.get()) == 0)
    {
        return false;
    }
    static_cast<void>(attribute.release());
    return true;
}

bool AddExtensionValue(EnvelopeFixture* fixture, const Bytes& encoded)
{
    return AddAttribute(fixture,
                        NID_ext_req,
                        std::string_view{reinterpret_cast<const char*>(encoded.data()), encoded.size()},
                        V_ASN1_SEQUENCE);
}

TEST(CsrDerTest, EmptyAttributesAreValidAndEnvelopeIsNotAnUnsignedRequest)
{
    auto encoded = EncodeParameters({{"2.5.4.3", "device"}}, {}, {});
    ASSERT_TRUE(encoded.has_value());
    const auto* cursor = encoded->data();
    auto* fields = d2i_ASN1_SEQUENCE_ANY(nullptr, &cursor, static_cast<long>(encoded->size()));
    ASSERT_NE(fields, nullptr);
    ASSERT_EQ(sk_ASN1_TYPE_num(fields), 2);
    EXPECT_EQ(ASN1_TYPE_get(sk_ASN1_TYPE_value(fields, 0)), V_ASN1_SEQUENCE);
    EXPECT_EQ(ASN1_TYPE_get(sk_ASN1_TYPE_value(fields, 1)), V_ASN1_SET);
    sk_ASN1_TYPE_pop_free(fields, ASN1_TYPE_free);
    cursor = encoded->data();
    RequestPtr full{d2i_X509_REQ(nullptr, &cursor, static_cast<long>(encoded->size())), X509_REQ_free};
    EXPECT_FALSE(full);
    RequestPtr request{X509_REQ_new(), X509_REQ_free};
    ASSERT_TRUE(request);
    ASSERT_TRUE(PopulateRequest(request.get(), encoded.value()).has_value());
    EXPECT_EQ(X509_REQ_get_attr_count(request.get()), 0);
    EXPECT_EQ(X509_REQ_get0_pubkey(request.get()), nullptr);
}

TEST(CsrDerTest, PopulatingPreservesBoundKeyVersionAndSignatureAndReplacesAttributes)
{
    const std::array<unsigned char, 32> raw_key{1U};
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key{
        EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, raw_key.data(), raw_key.size()), EVP_PKEY_free};
    RequestPtr request{X509_REQ_new(), X509_REQ_free};
    ASSERT_TRUE(key);
    ASSERT_TRUE(request);
    ASSERT_EQ(X509_REQ_set_pubkey(request.get(), key.get()), 1);
    // OpenSSL accepts only PKCS#10 version 0 through this setter.
    ASSERT_EQ(X509_REQ_set_version(request.get(), 0L), 1);
    ASSERT_EQ(X509_REQ_add1_attr_by_NID(request.get(),
                                        NID_pkcs9_challengePassword,
                                        MBSTRING_UTF8,
                                        reinterpret_cast<const unsigned char*>("old"),
                                        3),
              1);
    auto* signature = ASN1_BIT_STRING_new();
    ASSERT_NE(signature, nullptr);
    unsigned char signature_data[] = {0xA5U, 0x5AU};
    ASSERT_EQ(ASN1_BIT_STRING_set(signature, signature_data, 2), 1);
    X509_REQ_set0_signature(request.get(), signature);
    std::unique_ptr<X509_ALGOR, decltype(&X509_ALGOR_free)> algorithm{X509_ALGOR_new(), X509_ALGOR_free};
    ASSERT_TRUE(algorithm);
    ASSERT_EQ(X509_ALGOR_set0(algorithm.get(), OBJ_nid2obj(NID_ED25519), V_ASN1_UNDEF, nullptr), 1);
    ASSERT_EQ(X509_REQ_set1_signature_algo(request.get(), algorithm.get()), 1);
    auto* bound_key = X509_REQ_get0_pubkey(request.get());
    auto encoded = EncodeParameters({{"2.5.4.3", "new"}}, {}, {});
    ASSERT_TRUE(encoded.has_value());
    ASSERT_TRUE(PopulateRequest(request.get(), encoded.value()).has_value());
    EXPECT_EQ(X509_REQ_get0_pubkey(request.get()), bound_key);
    EXPECT_EQ(X509_REQ_get_version(request.get()), 0L);
    EXPECT_EQ(X509_REQ_get_attr_count(request.get()), 0);
    const ASN1_BIT_STRING* actual_signature = nullptr;
    const X509_ALGOR* actual_algorithm = nullptr;
    X509_REQ_get0_signature(request.get(), &actual_signature, &actual_algorithm);
    ASSERT_NE(actual_signature, nullptr);
    EXPECT_EQ(ASN1_STRING_length(actual_signature), 2);
    EXPECT_EQ(ASN1_STRING_get0_data(actual_signature)[0], 0xA5U);
    EXPECT_EQ(X509_ALGOR_cmp(actual_algorithm, algorithm.get()), 0);
}

TEST(CsrDerTest, RejectsMalformedBerNonMinimalAndInvalidPrimitiveEncodings)
{
    const std::vector<Bytes> malformed{{},
                                       {0x30U},
                                       {0x30U, 0x80U, 0U, 0U},
                                       {0x30U, 0x81U, 0U},
                                       {0x30U, 0x82U, 0U, 0x80U},
                                       {0x30U, 0xFFU},
                                       {0x10U, 0U},
                                       {0x02U, 0U},
                                       {0x02U, 2U, 0U, 1U},
                                       {0x02U, 2U, 0xFFU, 0xFFU},
                                       {0x01U, 1U, 1U},
                                       {0x01U, 0U},
                                       {0x06U, 0U},
                                       {0x06U, 2U, 0x80U, 0x2AU},
                                       {0x06U, 1U, 0x80U},
                                       {0x0CU, 2U, 0xC0U, 0x80U},
                                       {0x0CU, 1U, 0U},
                                       {0x0CU, 3U, 0xEDU, 0xA0U, 0x80U},
                                       {0x2CU, 3U, 0x0CU, 1U, 'x'},
                                       {0x13U, 1U, '@'},
                                       {0x16U, 1U, 0x80U},
                                       {0x1EU, 2U, 0xD8U, 0U},
                                       {0x03U, 2U, 1U, 1U},
                                       {0x05U, 1U, 0U},
                                       {0x1FU, 1U, 0U},
                                       {0x31U, 6U, 0x02U, 1U, 2U, 0x02U, 1U, 1U},
                                       {0x30U, 2U, 0x30U, 2U},
                                       {0x30U, 0U, 0U}};
    RequestPtr request{X509_REQ_new(), X509_REQ_free};
    ASSERT_TRUE(request);
    for (const auto& bytes : malformed)
    {
        EXPECT_FALSE(IsCanonicalDer(bytes));
        EXPECT_FALSE(PopulateRequest(request.get(), bytes).has_value());
    }
    EXPECT_TRUE(IsCanonicalDer(Bytes{0x04U, 3U, 0xFFU, 0U, 0x80U}));
    EXPECT_TRUE(IsCanonicalDer(Bytes{0x01U, 1U, 0xFFU}));
    EXPECT_TRUE(IsCanonicalDer(Bytes{0x02U, 2U, 0U, 0x80U}));
    EXPECT_TRUE(IsCanonicalDer(Bytes{0x06U, 2U, 0x88U, 0x37U}));
    EXPECT_TRUE(IsCanonicalDer(Bytes{0x31U, 6U, 0x02U, 1U, 1U, 0x02U, 1U, 2U}));
}

TEST(CsrDerTest, RejectsTrailingTruncatedOversizedAndExcessivelyNestedDataWithoutMutation)
{
    auto encoded = EncodeParameters({{"2.5.4.3", "device"}}, {}, {});
    ASSERT_TRUE(encoded.has_value());
    RequestPtr request{X509_REQ_new(), X509_REQ_free};
    ASSERT_TRUE(request);
    ASSERT_TRUE(PopulateRequest(request.get(), encoded.value()).has_value());
    auto trailing = encoded.value();
    trailing.push_back(0U);
    EXPECT_FALSE(PopulateRequest(request.get(), trailing).has_value());
    auto truncated = encoded.value();
    truncated.pop_back();
    EXPECT_FALSE(PopulateRequest(request.get(), truncated).has_value());
    EXPECT_FALSE(PopulateRequest(nullptr, encoded.value()).has_value());
    const Bytes oversized(bounds::kMaxInputDerBytes + 1U, 0U);
    EXPECT_FALSE(PopulateRequest(request.get(), oversized).has_value());
    Bytes nested{0x30U, 0U};
    for (unsigned i = 0U; i < 16U; ++i)
    {
        const auto size = static_cast<std::uint8_t>(nested.size());
        nested.insert(nested.begin(), {0x30U, size});
    }
    EXPECT_FALSE(IsCanonicalDer(nested));
    EXPECT_FALSE(PopulateRequest(request.get(), nested).has_value());
    const auto* value = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(X509_REQ_get_subject_name(request.get()), 0));
    EXPECT_EQ(std::string(reinterpret_cast<const char*>(ASN1_STRING_get0_data(value)),
                          static_cast<std::size_t>(ASN1_STRING_length(value))),
              "device");
}

TEST(CsrDerTest, RejectsUnknownDuplicateMultivaluedAndWronglyTypedAttributes)
{
    RequestPtr request{X509_REQ_new(), X509_REQ_free};
    ASSERT_TRUE(request);
    for (int nid : {NID_pkcs9_unstructuredName, NID_ms_ext_req})
    {
        auto fixture = Fixture();
        ASSERT_TRUE(fixture);
        ASSERT_TRUE(AddAttribute(fixture.get(), nid));
        EXPECT_FALSE(PopulateRequest(request.get(), EncodeFixture(fixture.get())).has_value());
    }
    auto duplicate = Fixture();
    ASSERT_TRUE(duplicate);
    ASSERT_TRUE(AddAttribute(duplicate.get(), NID_pkcs9_challengePassword));
    ASSERT_TRUE(AddAttribute(duplicate.get(), NID_pkcs9_challengePassword));
    EXPECT_FALSE(PopulateRequest(request.get(), EncodeFixture(duplicate.get())).has_value());
    auto multivalued = Fixture();
    ASSERT_TRUE(multivalued);
    ASSERT_TRUE(AddAttribute(multivalued.get(), NID_pkcs9_challengePassword));
    ASSERT_EQ(
        X509_ATTRIBUTE_set1_data(sk_X509_ATTRIBUTE_value(multivalued->attributes, 0), V_ASN1_UTF8STRING, "other", 5),
        1);
    EXPECT_FALSE(PopulateRequest(request.get(), EncodeFixture(multivalued.get())).has_value());
    auto wrong_type = Fixture();
    ASSERT_TRUE(wrong_type);
    ASSERT_TRUE(AddAttribute(wrong_type.get(), NID_pkcs9_challengePassword, "x", V_ASN1_IA5STRING));
    EXPECT_FALSE(PopulateRequest(request.get(), EncodeFixture(wrong_type.get())).has_value());
    auto boolean = Fixture();
    ASSERT_TRUE(boolean);
    ASSERT_TRUE(AddAttribute(boolean.get(), NID_pkcs9_challengePassword));
    auto* value = X509_ATTRIBUTE_get0_type(sk_X509_ATTRIBUTE_value(boolean->attributes, 0), 0);
    ASSERT_NE(value, nullptr);
    ASN1_TYPE_set(value, V_ASN1_BOOLEAN, reinterpret_cast<void*>(1));
    EXPECT_FALSE(PopulateRequest(request.get(), EncodeFixture(boolean.get())).has_value());
    auto too_long = Fixture();
    ASSERT_TRUE(too_long);
    ASSERT_TRUE(AddAttribute(too_long.get(),
                             NID_pkcs9_challengePassword,
                             std::string(bounds::kMaxChallengePasswordBytes + 1U, 'x'),
                             V_ASN1_UTF8STRING));
    EXPECT_FALSE(PopulateRequest(request.get(), EncodeFixture(too_long.get())).has_value());
}

TEST(CsrDerTest, ExtensionRequestRejectsDuplicateOidsCountsAndRepeatedAttributes)
{
    RequestPtr request{X509_REQ_new(), X509_REQ_free};
    ASSERT_TRUE(request);
    auto duplicate_oids = Fixture();
    ASSERT_TRUE(duplicate_oids);
    ASSERT_TRUE(AddRequestedExtensions(duplicate_oids.get(), true, 2U));
    EXPECT_FALSE(PopulateRequest(request.get(), EncodeFixture(duplicate_oids.get())).has_value());
    auto duplicate_attributes = Fixture();
    ASSERT_TRUE(duplicate_attributes);
    ASSERT_TRUE(AddRequestedExtensions(duplicate_attributes.get()));
    ASSERT_TRUE(AddRequestedExtensions(duplicate_attributes.get()));
    EXPECT_FALSE(PopulateRequest(request.get(), EncodeFixture(duplicate_attributes.get())).has_value());
    auto maximum = Fixture();
    ASSERT_TRUE(maximum);
    ASSERT_TRUE(AddRequestedExtensions(maximum.get(), false, bounds::kMaxExtensions));
    EXPECT_TRUE(PopulateRequest(request.get(), EncodeFixture(maximum.get())).has_value());
    auto excessive = Fixture();
    ASSERT_TRUE(excessive);
    ASSERT_TRUE(AddRequestedExtensions(excessive.get(), false, bounds::kMaxExtensions + 1U));
    EXPECT_FALSE(PopulateRequest(request.get(), EncodeFixture(excessive.get())).has_value());
}

TEST(CsrDerTest, RejectsNoncanonicalExtensionWrappersButDoesNotInterpretCustomOctets)
{
    RequestPtr request{X509_REQ_new(), X509_REQ_free};
    ASSERT_TRUE(request);
    // Raw fixtures describe the open type inside the attribute, including
    // malformed encodings that a normal OpenSSL extension encoder normalizes.
    const std::vector<Bytes> malformed{{0x30U, 0U},
                                       {0x30U, 3U, 0x04U, 1U, 0U},
                                       {0x30U, 0x0CU, 0x30U, 0x0AU, 0x06U, 3U, 0x2AU, 3U, 4U, 0x01U, 1U, 0U, 0x04U, 0U},
                                       {0x30U, 0x0CU, 0x30U, 0x0AU, 0x06U, 3U, 0x2AU, 3U, 4U, 0x01U, 1U, 1U, 0x04U, 0U},
                                       {0x30U, 0x0BU, 0x30U, 9U, 0x06U, 3U, 0x2AU, 3U, 4U, 0x04U, 0x81U, 1U, 0xFFU}};
    for (const auto& bytes : malformed)
    {
        auto fixture = Fixture();
        ASSERT_TRUE(fixture);
        ASSERT_TRUE(AddExtensionValue(fixture.get(), bytes));
        EXPECT_FALSE(PopulateRequest(request.get(), EncodeFixture(fixture.get())).has_value());
    }
    const Bytes opaque{0x30U, 0x0AU, 0x30U, 8U, 0x06U, 3U, 0x2AU, 3U, 4U, 0x04U, 1U, 0xFFU};
    auto fixture = Fixture();
    ASSERT_TRUE(fixture);
    ASSERT_TRUE(AddExtensionValue(fixture.get(), opaque));
    EXPECT_TRUE(PopulateRequest(request.get(), EncodeFixture(fixture.get())).has_value());
}

TEST(CsrDerTest, CachedNameCannotHideNonminimalLengthsOrEmptyRdns)
{
    auto encoded = EncodeParameters({{"2.5.4.3", "device"}}, {}, {});
    ASSERT_TRUE(encoded.has_value());
    ASSERT_LT(encoded.value()[1], 128U);
    ASSERT_EQ(encoded.value()[2], 0x30U);
    ASSERT_LT(encoded.value()[3], 128U);
    RequestPtr request{X509_REQ_new(), X509_REQ_free};
    ASSERT_TRUE(request);
    auto nonminimal = encoded.value();
    ++nonminimal[1];
    nonminimal.insert(nonminimal.begin() + 3, 0x81U);
    EXPECT_FALSE(PopulateRequest(request.get(), nonminimal).has_value());
    // A canonical empty SET appended to Name may be flattened/cached by d2i.
    auto empty_rdn = encoded.value();
    const auto name_end = static_cast<std::size_t>(4U + empty_rdn[3]);
    empty_rdn[1] += 2U;
    empty_rdn[3] += 2U;
    empty_rdn.insert(empty_rdn.begin() + static_cast<std::ptrdiff_t>(name_end), {0x31U, 0U});
    EXPECT_TRUE(IsCanonicalDer(empty_rdn));
    EXPECT_FALSE(PopulateRequest(request.get(), empty_rdn).has_value());
}

TEST(CsrDerTest, RejectsInvalidNameValuesAndMultivaluedRdns)
{
    RequestPtr request{X509_REQ_new(), X509_REQ_free};
    ASSERT_TRUE(request);
    auto empty = FixturePtr{EnvelopeFixture_new(), EnvelopeFixture_free};
    ASSERT_TRUE(empty);
    EXPECT_FALSE(PopulateRequest(request.get(), EncodeFixture(empty.get())).has_value());
    auto country = Fixture();
    ASSERT_TRUE(country);
    ASSERT_EQ(X509_NAME_add_entry_by_NID(country->subject,
                                         NID_countryName,
                                         V_ASN1_UTF8STRING,
                                         reinterpret_cast<const unsigned char*>("ABC"),
                                         3,
                                         -1,
                                         0),
              1);
    EXPECT_FALSE(PopulateRequest(request.get(), EncodeFixture(country.get())).has_value());
    auto multivalued = Fixture();
    ASSERT_TRUE(multivalued);
    ASSERT_EQ(X509_NAME_add_entry_by_NID(multivalued->subject,
                                         NID_organizationalUnitName,
                                         MBSTRING_UTF8,
                                         reinterpret_cast<const unsigned char*>("unit"),
                                         4,
                                         -1,
                                         -1),
              1);
    EXPECT_FALSE(PopulateRequest(request.get(), EncodeFixture(multivalued.get())).has_value());
    for (const auto& text : {std::string{"a\0b", 3U}, std::string{"\xED\xA0\x80"}})
    {
        auto fixture = Fixture();
        ASSERT_TRUE(fixture);
        ASSERT_EQ(X509_NAME_ENTRY_set_data(X509_NAME_get_entry(fixture->subject, 0),
                                           V_ASN1_UTF8STRING,
                                           reinterpret_cast<const unsigned char*>(text.data()),
                                           static_cast<int>(text.size())),
                  1);
        EXPECT_FALSE(PopulateRequest(request.get(), EncodeFixture(fixture.get())).has_value());
    }
}

TEST(CsrDerTest, EnforcesDirectEncoderBounds)
{
    const std::vector<SubjectAttribute> subject{{"2.5.4.3", "device"}};
    EXPECT_FALSE(EncodeParameters({}, {}, {}).has_value());
    EXPECT_FALSE(EncodeParameters({{"CN", "device"}}, {}, {}).has_value());
    EXPECT_FALSE(EncodeParameters({{"2.5.4.3", std::string{"a\0b", 3U}}}, {}, {}).has_value());
    EXPECT_FALSE(EncodeParameters(subject, {}, std::string(bounds::kMaxChallengePasswordBytes + 1U, 'x')).has_value());
    EXPECT_FALSE(
        EncodeParameters(subject, {{"1.2.3.4", false, "DER:05:00"}, {"1.2.3.4", true, "DER:05:00"}}, {}).has_value());
    std::vector<SubjectAttribute> maximum(bounds::kMaxSubjectEntries, {"2.5.4.11", "unit"});
    auto encoded = EncodeParameters(maximum, {}, {});
    ASSERT_TRUE(encoded.has_value());
    RequestPtr request{X509_REQ_new(), X509_REQ_free};
    ASSERT_TRUE(request);
    EXPECT_TRUE(PopulateRequest(request.get(), encoded.value()).has_value());
    maximum.push_back({"2.5.4.11", "excess"});
    EXPECT_FALSE(EncodeParameters(maximum, {}, {}).has_value());
    EXPECT_FALSE(EncodeParameters({{"1.2.3.4", std::string(bounds::kMaxValueBytes + 1U, 'x')}}, {}, {}).has_value());
    const std::vector<SubjectAttribute> aggregate(10U, {"1.2.3.4", std::string(bounds::kMaxValueBytes, 'x')});
    EXPECT_FALSE(EncodeParameters(aggregate, {}, {}).has_value());
}

TemplateRecord Template()
{
    return {"enrollment",
            "device-key",
            "ECDSA_SHA256",
            {{"2.5.4.6", "${country}"}, {"2.5.4.3", "${device}"}, {"2.5.4.11", "first"}, {"2.5.4.11", "second"}},
            {{"2.5.4.10", "${issuer}"}, {"2.5.4.11", "é"}},
            {{"2.5.29.15", true, "digitalSignature"}, {"1.2.3.4", false, "DER:FF:00:80"}},
            "https://enrollment.example/é"};
}

TEST(CsrDerTemplateTest, RoundTripsOrderedPlaceholdersMetadataAndExtensionConfiguration)
{
    const auto source = Template();
    auto encoded = EncodeTemplate(source);
    ASSERT_TRUE(encoded.has_value());
    EXPECT_TRUE(IsCanonicalDer(encoded.value()));
    auto decoded = DecodeTemplate(encoded.value());
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->id, source.id);
    EXPECT_EQ(decoded->key_resource, source.key_resource);
    EXPECT_EQ(decoded->algorithm, source.algorithm);
    EXPECT_EQ(decoded->submission_url, source.submission_url);
    ASSERT_EQ(decoded->subject.size(), source.subject.size());
    ASSERT_EQ(decoded->issuer.size(), source.issuer.size());
    ASSERT_EQ(decoded->extensions.size(), source.extensions.size());
    for (std::size_t i = 0U; i < source.subject.size(); ++i)
    {
        EXPECT_EQ(decoded->subject[i].oid, source.subject[i].oid);
        EXPECT_EQ(decoded->subject[i].value, source.subject[i].value);
    }
    for (std::size_t i = 0U; i < source.issuer.size(); ++i)
    {
        EXPECT_EQ(decoded->issuer[i].oid, source.issuer[i].oid);
        EXPECT_EQ(decoded->issuer[i].value, source.issuer[i].value);
    }
    for (std::size_t i = 0U; i < source.extensions.size(); ++i)
    {
        EXPECT_EQ(decoded->extensions[i].oid, source.extensions[i].oid);
        EXPECT_EQ(decoded->extensions[i].critical, source.extensions[i].critical);
        EXPECT_EQ(decoded->extensions[i].value, source.extensions[i].value);
    }
    // Generation, unlike storage, cannot encode an unresolved country Name.
    EXPECT_FALSE(EncodeParameters(decoded->subject, decoded->extensions, {}).has_value());
    auto minimal = source;
    minimal.issuer.clear();
    minimal.extensions.clear();
    minimal.submission_url.clear();
    auto minimal_encoded = EncodeTemplate(minimal);
    ASSERT_TRUE(minimal_encoded.has_value());
    EXPECT_TRUE(DecodeTemplate(minimal_encoded.value()).has_value());
}

TEST(CsrDerTemplateTest, RejectsUnsupportedVersionTrailingDataAndOversizedDocuments)
{
    auto encoded = EncodeTemplate(Template());
    ASSERT_TRUE(encoded.has_value());
    auto unsupported = encoded.value();
    const std::array<std::uint8_t, 3> version{0x02U, 1U, 1U};
    const auto found = std::search(unsupported.begin(), unsupported.end(), version.begin(), version.end());
    ASSERT_NE(found, unsupported.end());
    *(found + 2) = 2U;
    EXPECT_TRUE(IsCanonicalDer(unsupported));
    EXPECT_FALSE(DecodeTemplate(unsupported).has_value());
    auto trailing = encoded.value();
    trailing.push_back(0U);
    EXPECT_FALSE(DecodeTemplate(trailing).has_value());
    auto truncated = encoded.value();
    truncated.pop_back();
    EXPECT_FALSE(DecodeTemplate(truncated).has_value());
    EXPECT_FALSE(DecodeTemplate(Bytes(65537U, 0U)).has_value());
    auto excessive = Template();
    excessive.subject.assign(40U, {"1.2.3.4", std::string(bounds::kMaxValueBytes, 'x')});
    EXPECT_FALSE(EncodeTemplate(excessive).has_value());
}

TEST(CsrDerTemplateTest, DecoderRejectsInvalidTextAndExplicitDefaultFalse)
{
    auto source = Template();
    auto encoded = EncodeTemplate(source);
    ASSERT_TRUE(encoded.has_value());
    auto invalid_text = encoded.value();
    const auto id = std::search(invalid_text.begin(), invalid_text.end(), source.id.begin(), source.id.end());
    ASSERT_NE(id, invalid_text.end());
    *id = 0U;
    EXPECT_FALSE(DecodeTemplate(invalid_text).has_value());
    *id = 0x80U;
    EXPECT_FALSE(DecodeTemplate(invalid_text).has_value());
    // Decode the outer sequence as ANY, then alter only the extensions open
    // sequence. No production encoder is used to manufacture malformed DER.
    const auto* cursor = encoded->data();
    auto* fields = d2i_ASN1_SEQUENCE_ANY(nullptr, &cursor, static_cast<long>(encoded->size()));
    ASSERT_NE(fields, nullptr);
    ASSERT_EQ(sk_ASN1_TYPE_num(fields), 8);
    auto* extensions = sk_ASN1_TYPE_value(fields, 6);
    ASSERT_EQ(ASN1_TYPE_get(extensions), V_ASN1_SEQUENCE);
    const auto* bytes = ASN1_STRING_get0_data(extensions->value.sequence);
    Bytes changed(bytes, bytes + ASN1_STRING_length(extensions->value.sequence));
    // Both extension sequences fit short-form lengths in this fixture. Insert
    // DEFAULT FALSE before the second value and update its two parent lengths.
    ASSERT_EQ(changed[0], 0x30U);
    ASSERT_LT(changed[1], 128U);
    ASSERT_EQ(changed[2], 0x30U);
    const auto second = static_cast<std::size_t>(4U + changed[3]);
    ASSERT_LT(second + 4U, changed.size());
    ASSERT_EQ(changed[second], 0x30U);
    ASSERT_EQ(changed[second + 2U], 0x06U);
    const auto value_position = second + 4U + changed[second + 3U];
    ASSERT_LT(value_position, changed.size());
    ASSERT_EQ(changed[value_position], 0x0CU);
    changed[1] += 3U;
    changed[second + 1U] += 3U;
    changed.insert(changed.begin() + static_cast<std::ptrdiff_t>(value_position), {0x01U, 1U, 0U});
    ASSERT_EQ(ASN1_STRING_set(extensions->value.sequence, changed.data(), static_cast<int>(changed.size())), 1);
    const int size = i2d_ASN1_SEQUENCE_ANY(fields, nullptr);
    ASSERT_GT(size, 0);
    Bytes malformed(static_cast<std::size_t>(size));
    auto* output = malformed.data();
    ASSERT_EQ(i2d_ASN1_SEQUENCE_ANY(fields, &output), size);
    sk_ASN1_TYPE_pop_free(fields, ASN1_TYPE_free);
    EXPECT_TRUE(IsCanonicalDer(malformed));
    EXPECT_FALSE(DecodeTemplate(malformed).has_value());
}

TEST(CsrDerTemplateTest, RejectsInvalidUtf8NulOidsDuplicatesAndFieldBounds)
{
    auto value = Template();
    value.id = std::string{"a\0b", 3U};
    EXPECT_FALSE(EncodeTemplate(value).has_value());
    value = Template();
    value.issuer[0].value = "\xF4\x90\x80\x80";
    EXPECT_FALSE(EncodeTemplate(value).has_value());
    value = Template();
    value.subject[0].oid = "1.02.3";
    EXPECT_FALSE(EncodeTemplate(value).has_value());
    value = Template();
    value.extensions.push_back(value.extensions[0]);
    EXPECT_FALSE(EncodeTemplate(value).has_value());
    value = Template();
    value.key_resource.assign(65U, 'x');
    EXPECT_FALSE(EncodeTemplate(value).has_value());
    value = Template();
    value.id.assign(129U, 'x');
    EXPECT_FALSE(EncodeTemplate(value).has_value());
    value = Template();
    value.subject.clear();
    EXPECT_FALSE(EncodeTemplate(value).has_value());
    value = Template();
    value.issuer.assign(bounds::kMaxSubjectEntries + 1U, {"2.5.4.11", "unit"});
    EXPECT_FALSE(EncodeTemplate(value).has_value());
    // A placeholder/config is retained as text; parsing is generation's job.
    value = Template();
    value.extensions[0].value = "${usage}";
    EXPECT_TRUE(EncodeTemplate(value).has_value());
}
}  // namespace
}  // namespace score::crypto::csr::der

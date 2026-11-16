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

#include "score/crypto/src/api/csr/csr_template.hpp"
#include "score/crypto/src/common/csr_der.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/csr/csr_processing.hpp"
#include <gtest/gtest.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

namespace score::crypto
{
namespace
{
using Bytes = std::vector<std::uint8_t>;
NativeCsrProcessing processing;

class CsrTemplateStorageTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        value_.id = "device-template";
        value_.key_resource = "device-key";
        value_.algorithm = "ECDSA-SHA256";
        ASSERT_TRUE(value_.subject.Add(processing, CsrOid::kCommonName, "${serial}").has_value());
    }

    static void ExpectSubjectEqual(const CsrSubject& actual, const CsrSubject& expected)
    {
        ASSERT_EQ(actual.Attributes().size(), expected.Attributes().size());
        for (std::size_t i = 0; i < expected.Attributes().size(); ++i)
        {
            EXPECT_EQ(actual.Attributes()[i].oid, expected.Attributes()[i].oid);
            EXPECT_EQ(actual.Attributes()[i].value, expected.Attributes()[i].value);
        }
    }

    CsrTemplate value_;
};

TEST_F(CsrTemplateStorageTest, RoundTripsMetadataOrderedPlaceholdersAndCriticalCustomExtensions)
{
    value_.submission_url = "https://enrollment.example/csr";
    // Storage must not encode these values as an X.509 Name: even a country
    // placeholder is retained verbatim until application-side substitution.
    ASSERT_TRUE(value_.subject.Add(processing, CsrOid::kCountry, "${country}").has_value());
    ASSERT_TRUE(value_.subject.Add(processing, CsrOid::kOrganization, "organization-é").has_value());
    ASSERT_TRUE(value_.subject.Add(processing, CsrOid::kOrganizationalUnit, "first-${unit}").has_value());
    ASSERT_TRUE(value_.subject.Add(processing, CsrOid::kOrganizationalUnit, "second").has_value());
    ASSERT_TRUE(value_.subject.Add(processing, "1.2.3.4.5", "custom-${serial}").has_value());
    ASSERT_TRUE(value_.issuer.Add(processing, CsrOid::kCommonName, "issuer-${issuer}").has_value());
    ASSERT_TRUE(value_.issuer.Add(processing, CsrOid::kOrganization, "${organization}").has_value());
    const std::array<std::uint8_t, 4> extension_der{0x04U, 0x02U, 0xABU, 0xCDU};
    auto custom = CsrExtension::CustomDer(processing, "1.2.3.4.5", extension_der, true);
    ASSERT_TRUE(custom.has_value());
    value_.extensions = {
        custom.value(), {"2.5.29.17", false, "DNS:device.example"}, {"2.5.29.15", true, "digitalSignature"}};

    auto encoded = DerCsrTemplateStorage::Save(processing, value_);
    ASSERT_TRUE(encoded.has_value());
    ASSERT_FALSE(encoded->empty());
    EXPECT_EQ(encoded->front(), 0x30U);
    EXPECT_TRUE(csr::der::IsCanonicalDer(encoded.value()));
    auto record = csr::der::DecodeTemplate(encoded.value());
    ASSERT_TRUE(record.has_value());
    ASSERT_EQ(record->subject.size(), value_.subject.Attributes().size());
    EXPECT_EQ(record->subject[1].oid, GetCsrOid(CsrOid::kCountry));
    EXPECT_EQ(record->subject[1].value, "${country}");

    DerCsrTemplateStorage storage{processing, encoded.value()};
    auto loaded = storage.Load(value_.id);
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(loaded->id, value_.id);
    EXPECT_EQ(loaded->key_resource, value_.key_resource);
    EXPECT_EQ(loaded->algorithm, value_.algorithm);
    EXPECT_EQ(loaded->submission_url, value_.submission_url);
    EXPECT_FALSE(loaded->key_resource.truncated());
    EXPECT_FALSE(loaded->algorithm.truncated());
    ExpectSubjectEqual(loaded->subject, value_.subject);
    ExpectSubjectEqual(loaded->issuer, value_.issuer);
    ASSERT_EQ(loaded->extensions.size(), value_.extensions.size());
    for (std::size_t i = 0; i < value_.extensions.size(); ++i)
    {
        EXPECT_EQ(loaded->extensions[i].oid, value_.extensions[i].oid);
        EXPECT_EQ(loaded->extensions[i].critical, value_.extensions[i].critical);
        EXPECT_EQ(loaded->extensions[i].value, value_.extensions[i].value);
    }
    auto reencoded = DerCsrTemplateStorage::Save(processing, loaded.value());
    ASSERT_TRUE(reencoded.has_value());
    EXPECT_EQ(reencoded.value(), encoded.value());
}

TEST_F(CsrTemplateStorageTest, AllowsEmptyOptionalIssuerUrlAndExtensions)
{
    auto encoded = DerCsrTemplateStorage::Save(processing, value_);
    ASSERT_TRUE(encoded.has_value());
    auto loaded = DerCsrTemplateStorage{processing, encoded.value()}.Load(value_.id);
    ASSERT_TRUE(loaded.has_value());
    EXPECT_TRUE(loaded->issuer.Attributes().empty());
    EXPECT_TRUE(loaded->submission_url.empty());
    EXPECT_TRUE(loaded->extensions.empty());
    ExpectSubjectEqual(loaded->subject, value_.subject);
}

TEST_F(CsrTemplateStorageTest, RejectsWrongRequestedId)
{
    auto encoded = DerCsrTemplateStorage::Save(processing, value_);
    ASSERT_TRUE(encoded.has_value());
    DerCsrTemplateStorage storage{processing, encoded.value()};
    EXPECT_TRUE(storage.Load(value_.id).has_value());
    EXPECT_FALSE(storage.Load("another-template").has_value());
    EXPECT_FALSE(storage.Load("").has_value());
}

TEST_F(CsrTemplateStorageTest, RejectsEveryTruncationAndTrailingData)
{
    auto encoded = DerCsrTemplateStorage::Save(processing, value_);
    ASSERT_TRUE(encoded.has_value());
    for (std::size_t size = 0; size < encoded->size(); ++size)
    {
        SCOPED_TRACE(size);
        Bytes truncated{encoded->begin(), std::next(encoded->begin(), static_cast<Bytes::difference_type>(size))};
        EXPECT_FALSE((DerCsrTemplateStorage{processing, std::move(truncated)}.Load(value_.id).has_value()));
    }
    for (const std::uint8_t byte : {0x00U, 0x01U, 0x30U})
    {
        auto trailing = encoded.value();
        trailing.push_back(byte);
        EXPECT_FALSE((DerCsrTemplateStorage{processing, std::move(trailing)}.Load(value_.id).has_value()));
    }
}

TEST_F(CsrTemplateStorageTest, RejectsNoncanonicalShortAndLongFormLengths)
{
    for (const bool long_form : {false, true})
    {
        SCOPED_TRACE(long_form);
        auto value = value_;
        if (long_form)
        {
            value.id.assign(128U, 't');
        }
        auto encoded = DerCsrTemplateStorage::Save(processing, value);
        ASSERT_TRUE(encoded.has_value());
        ASSERT_GT(encoded->size(), 2U);
        auto noncanonical = encoded.value();
        ASSERT_EQ((noncanonical[1] & 0x80U) != 0U, long_form);
        if (noncanonical[1] < 0x80U)
        {
            // The same content length, needlessly encoded in long form.
            noncanonical.insert(noncanonical.begin() + 1, 0x81U);
        }
        else
        {
            // Add a leading zero to an existing long-form length.
            ++noncanonical[1];
            noncanonical.insert(noncanonical.begin() + 2, 0x00U);
        }
        EXPECT_FALSE((DerCsrTemplateStorage{processing, std::move(noncanonical)}.Load(value.id).has_value()));
    }
}

TEST_F(CsrTemplateStorageTest, RejectsUnsupportedVersions)
{
    auto encoded = DerCsrTemplateStorage::Save(processing, value_);
    ASSERT_TRUE(encoded.has_value());
    ASSERT_GT(encoded->size(), 2U);
    const std::size_t offset = 2U + (encoded.value()[1] < 0x80U ? 0U : (encoded.value()[1] & 0x7FU));
    ASSERT_GT(encoded->size(), offset + 2U);
    // Version is the first INTEGER in the version-1 template SEQUENCE.
    ASSERT_EQ(encoded.value()[offset], 0x02U);
    ASSERT_EQ(encoded.value()[offset + 1U], 0x01U);
    ASSERT_EQ(encoded.value()[offset + 2U], 0x01U);
    for (const std::uint8_t version : {0x00U, 0x02U, 0x7FU})
    {
        auto unsupported = encoded.value();
        unsupported[offset + 2U] = version;
        EXPECT_FALSE((DerCsrTemplateStorage{processing, std::move(unsupported)}.Load(value_.id).has_value()));
    }
}

TEST_F(CsrTemplateStorageTest, RejectsOversizedDerDocuments)
{
    EXPECT_FALSE((DerCsrTemplateStorage{processing, Bytes(65537U, 0x00U)}.Load(value_.id).has_value()));
    value_.issuer = CsrSubject{};
    for (std::size_t i = 0; i < 32U; ++i)
    {
        ASSERT_TRUE(value_.issuer.Add(processing, CsrOid::kOrganizationalUnit, std::string(2048U, 'x')).has_value());
    }
    // Request and per-attribute bounds pass; issuer metadata pushes the stored
    // template beyond 64 KiB without enlarging the PKCS#10 request input.
    EXPECT_FALSE(DerCsrTemplateStorage::Save(processing, value_).has_value());
}

TEST_F(CsrTemplateStorageTest, RejectsInvalidMetadataOnSave)
{
    for (const auto& invalid :
         std::vector<std::string>{"", std::string(129U, 'x'), std::string{"x\0y", 3U}, std::string{"\x80"}})
    {
        auto value = value_;
        value.id = invalid;
        EXPECT_FALSE(DerCsrTemplateStorage::Save(processing, value).has_value());
    }
    for (const auto& invalid :
         std::vector<std::string>{"", std::string(65U, 'x'), std::string{"x\0y", 3U}, std::string{"\x80"}})
    {
        auto value = value_;
        value.key_resource = invalid;
        EXPECT_FALSE(DerCsrTemplateStorage::Save(processing, value).has_value());
        value = value_;
        value.algorithm = invalid;
        EXPECT_FALSE(DerCsrTemplateStorage::Save(processing, value).has_value());
    }
    for (const auto& invalid :
         std::vector<std::string>{std::string(2049U, 'x'), std::string{"x\0y", 3U}, std::string{"\x80"}})
    {
        auto value = value_;
        value.submission_url = invalid;
        EXPECT_FALSE(DerCsrTemplateStorage::Save(processing, value).has_value());
    }
}

TEST_F(CsrTemplateStorageTest, AcceptsMetadataAndSubjectIssuerBoundsWithoutTruncation)
{
    value_.id.assign(128U, 't');
    value_.key_resource = std::string(ResourceId::max_capacity, 'k');
    value_.algorithm = std::string(AlgorithmId::max_capacity, 'a');
    value_.submission_url.assign(2048U, 'u');
    value_.subject = CsrSubject{};
    ASSERT_TRUE(value_.subject.Add(processing, CsrOid::kCommonName, std::string(2048U, 's')).has_value());
    for (std::size_t i = 1; i < 64U; ++i)
    {
        ASSERT_TRUE(value_.subject.Add(processing, CsrOid::kOrganizationalUnit, "${unit}").has_value());
    }
    for (std::size_t i = 0; i < 64U; ++i)
    {
        ASSERT_TRUE(value_.issuer.Add(processing, CsrOid::kOrganizationalUnit, "${issuer}").has_value());
    }
    auto encoded = DerCsrTemplateStorage::Save(processing, value_);
    ASSERT_TRUE(encoded.has_value());
    auto loaded = DerCsrTemplateStorage{processing, encoded.value()}.Load(value_.id);
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(loaded->id, value_.id);
    EXPECT_EQ(loaded->key_resource, value_.key_resource);
    EXPECT_EQ(loaded->algorithm, value_.algorithm);
    EXPECT_EQ(loaded->submission_url, value_.submission_url);
    EXPECT_FALSE(loaded->key_resource.truncated());
    EXPECT_FALSE(loaded->algorithm.truncated());
    ExpectSubjectEqual(loaded->subject, value_.subject);
    ExpectSubjectEqual(loaded->issuer, value_.issuer);
}

TEST_F(CsrTemplateStorageTest, RejectsNulAndMalformedUtf8InDecodedMetadata)
{
    value_.submission_url = "https://enrollment.example/csr";
    auto encoded = DerCsrTemplateStorage::Save(processing, value_);
    ASSERT_TRUE(encoded.has_value());
    for (const auto& field : std::vector<std::string>{value_.id,
                                                      std::string{std::string_view{value_.key_resource}},
                                                      std::string{std::string_view{value_.algorithm}},
                                                      value_.submission_url})
    {
        SCOPED_TRACE(field);
        for (const std::uint8_t invalid : {0x00U, 0x80U})
        {
            auto malformed = encoded.value();
            auto found = std::search(malformed.begin(), malformed.end(), field.begin(), field.end());
            ASSERT_NE(found, malformed.end());
            // Preserve all lengths and tags, corrupting only the metadata text.
            *found = invalid;
            auto requested_id = value_.id;
            if (field == value_.id)
            {
                requested_id[0] = static_cast<char>(invalid);
            }
            EXPECT_FALSE((DerCsrTemplateStorage{processing, std::move(malformed)}.Load(requested_id).has_value()));
        }
    }
}

TEST_F(CsrTemplateStorageTest, RejectsDecodedResourceAndAlgorithmThatWouldTruncate)
{
    for (const bool oversized_key : {false, true})
    {
        SCOPED_TRACE(oversized_key);
        auto value = value_;
        value.id = "t";
        value.key_resource = "k";
        value.algorithm = "a";
        value.subject = CsrSubject{};
        ASSERT_TRUE(value.subject.Add(processing, CsrOid::kCommonName, "d").has_value());
        const std::string field(64U, oversized_key ? 'k' : 'a');
        if (oversized_key)
        {
            value.key_resource = field;
        }
        else
        {
            value.algorithm = field;
        }
        auto encoded = DerCsrTemplateStorage::Save(processing, value);
        ASSERT_TRUE(encoded.has_value());
        auto oversized = encoded.value();
        ASSERT_GT(oversized.size(), 2U);
        ASSERT_EQ(oversized[0], 0x30U);
        ASSERT_LT(oversized[1], 0x7FU);
        auto found = std::search(oversized.begin(), oversized.end(), field.begin(), field.end());
        ASSERT_NE(found, oversized.end());
        const auto offset = static_cast<std::size_t>(std::distance(oversized.begin(), found));
        ASSERT_GE(offset, 2U);
        ASSERT_EQ(oversized[offset - 2U], 0x0CU);  // UTF8String metadata field.
        ASSERT_EQ(oversized[offset - 1U], field.size());
        ++oversized[offset - 1U];
        oversized.insert(std::next(oversized.begin(), static_cast<Bytes::difference_type>(offset + field.size())), 'x');
        ++oversized[1];  // Maintain a canonical outer SEQUENCE length.
        EXPECT_FALSE((DerCsrTemplateStorage{processing, std::move(oversized)}.Load(value.id).has_value()));
    }
}

TEST_F(CsrTemplateStorageTest, RejectsEmptySubjectAndStructurallyInvalidExtensions)
{
    auto empty = value_;
    empty.subject = CsrSubject{};
    EXPECT_FALSE(DerCsrTemplateStorage::Save(processing, empty).has_value());
    for (const auto& extensions :
         std::vector<std::vector<CsrExtension>>{{{"1.2.3.4", false, ""}},
                                                {{"keyUsage", true, "digitalSignature"}},
                                                {{"1.2.3.4", false, "DER:05:00"}, {"1.2.3.4", true, "DER:05:00"}}})
    {
        auto value = value_;
        value.extensions = extensions;
        EXPECT_FALSE(DerCsrTemplateStorage::Save(processing, value).has_value());
    }
}

TEST_F(CsrTemplateStorageTest, RetainsStaticConfigWithoutParsingOrResolvingKeys)
{
    // Subject key identifier needs a bound public key when producing request
    // DER, but storage and preparation must perform structural validation only.
    value_.extensions = {{"2.5.29.14", false, "hash"}};
    auto encoded = DerCsrTemplateStorage::Save(processing, value_);
    ASSERT_TRUE(encoded.has_value());
    auto loaded = DerCsrTemplateStorage{processing, encoded.value()}.Load(value_.id);
    ASSERT_TRUE(loaded.has_value());
    CsrRuntimeValues runtime{{"serial", "device"}};
    auto prepared = CsrTemplateProcessor::Prepare(processing, loaded.value(), runtime, {{"2.5.4.3"}, {}});
    ASSERT_TRUE(prepared.has_value());
    ASSERT_EQ(prepared->request.extensions.size(), 1U);
    EXPECT_EQ(prepared->request.extensions[0].value, "hash");
    EXPECT_EQ(prepared->request.subject.Attributes()[0].value, "device");

    value_.extensions = {{"2.5.29.17", false, "DNS:${serial}"}};
    auto with_placeholder = DerCsrTemplateStorage::Save(processing, value_);
    ASSERT_TRUE(with_placeholder.has_value());
    auto stored = DerCsrTemplateStorage{processing, with_placeholder.value()}.Load(value_.id);
    ASSERT_TRUE(stored.has_value());
    ASSERT_EQ(stored->extensions.size(), 1U);
    EXPECT_EQ(stored->extensions[0].value, "DNS:${serial}");
    EXPECT_FALSE(CsrTemplateProcessor::Prepare(processing, stored.value(), runtime, {}).has_value());
}
}  // namespace
}  // namespace score::crypto

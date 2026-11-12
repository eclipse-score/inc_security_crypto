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

// Private offline oracle. OpenSSL assertions moved from score_api_csr_test.cpp
// and score_api_key_persistence_test.cpp, without SCORE APIs or daemon access.
// Fixed identities, profiles and extension bytes are test data, not policy.
#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{
using Request = std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)>;
constexpr std::size_t kMaxDerBytes = 64U * 1024U;

Request Parse(const char* path)
{
    std::ifstream input{path, std::ios::binary};
    if (!input.is_open())
    {
        ADD_FAILURE() << "Cannot read CSR evidence: " << path;
        return {nullptr, X509_REQ_free};
    }
    // Bounded even for malformed or oversized evidence files.
    std::vector<std::uint8_t> der(kMaxDerBytes + 1U);
    input.read(reinterpret_cast<char*>(der.data()), static_cast<std::streamsize>(der.size()));
    const auto size = input.gcount();
    if (input.bad() || !input.eof() || size <= 0 || size > static_cast<std::streamsize>(kMaxDerBytes))
    {
        ADD_FAILURE() << "Unreadable, empty or oversized CSR evidence: " << path;
        return {nullptr, X509_REQ_free};
    }
    der.resize(static_cast<std::size_t>(size));
    if (der.size() > static_cast<std::size_t>(std::numeric_limits<long>::max()))
    {
        ADD_FAILURE() << "Invalid CSR DER length: " << der.size();
        return {nullptr, X509_REQ_free};
    }
    const auto* cursor = der.data();
    Request request{d2i_X509_REQ(nullptr, &cursor, static_cast<long>(der.size())), X509_REQ_free};
    if (!request || cursor != der.data() + der.size())
    {
        ADD_FAILURE() << "Malformed CSR or trailing DER bytes";
        return {nullptr, X509_REQ_free};
    }
    return request;
}

std::string Text(const ASN1_STRING* value)
{
    if (value == nullptr || ASN1_STRING_length(value) < 0)
    {
        ADD_FAILURE() << "Invalid ASN.1 text";
        return {};
    }
    if (ASN1_STRING_length(value) == 0)
    {
        return {};
    }
    return {reinterpret_cast<const char*>(ASN1_STRING_get0_data(value)),
            static_cast<std::size_t>(ASN1_STRING_length(value))};
}

void ExpectCommonName(X509_REQ& request, const char* expected)
{
    auto* name = X509_REQ_get_subject_name(&request);
    ASSERT_NE(name, nullptr);
    const int index = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
    ASSERT_GE(index, 0);
    auto* entry = X509_NAME_get_entry(name, index);
    ASSERT_NE(entry, nullptr);
    ASSERT_EQ(Text(X509_NAME_ENTRY_get_data(entry)), expected);
    ASSERT_EQ(X509_NAME_get_index_by_NID(name, NID_commonName, index), -1);
}

void ExpectValidP256Csr(X509_REQ& request)
{
    auto* public_key = X509_REQ_get0_pubkey(&request);
    ASSERT_NE(public_key, nullptr);
    ASSERT_EQ(X509_REQ_get_signature_nid(&request), NID_ecdsa_with_SHA256);
    ASSERT_EQ(EVP_PKEY_is_a(public_key, "EC"), 1);
    char group_name[80]{};
    std::size_t group_name_length{};
    ASSERT_EQ(EVP_PKEY_get_group_name(public_key, group_name, sizeof(group_name), &group_name_length), 1);
    ASSERT_EQ(OBJ_txt2nid(group_name), NID_X9_62_prime256v1);
    ASSERT_EQ(X509_REQ_verify(&request, public_key), 1);
}

void VerifyValid(const char* path)
{
    auto request = Parse(path);
    ASSERT_NE(request, nullptr);
    EXPECT_EQ(X509_REQ_verify(request.get(), X509_REQ_get0_pubkey(request.get())), 1);
}

void VerifyP256(const char* path, const char* common_name)
{
    auto request = Parse(path);
    ASSERT_NE(request, nullptr);
    ASSERT_NO_FATAL_FAILURE(ExpectValidP256Csr(*request));
    ASSERT_NO_FATAL_FAILURE(ExpectCommonName(*request, common_name));
}

void VerifyRenewal(const char* first_path, const char* renewal_path, bool persistence)
{
    auto first = Parse(first_path);
    ASSERT_NE(first, nullptr);
    auto renewal = Parse(renewal_path);
    ASSERT_NE(renewal, nullptr);
    if (persistence)
    {
        ASSERT_NO_FATAL_FAILURE(ExpectValidP256Csr(*first));
        ASSERT_NO_FATAL_FAILURE(ExpectCommonName(*first, "first-enrollment"));
        ASSERT_NO_FATAL_FAILURE(ExpectValidP256Csr(*renewal));
        ASSERT_NO_FATAL_FAILURE(ExpectCommonName(*renewal, "renewed-enrollment"));
        ASSERT_EQ(EVP_PKEY_eq(X509_REQ_get0_pubkey(first.get()), X509_REQ_get0_pubkey(renewal.get())), 1)
            << "The device key changed across the daemon restart / power-cycle";
        EXPECT_EQ(X509_REQ_verify(renewal.get(), X509_REQ_get0_pubkey(first.get())), 1);
        EXPECT_NE(X509_NAME_cmp(X509_REQ_get_subject_name(first.get()), X509_REQ_get_subject_name(renewal.get())), 0);
    }
    else
    {
        ASSERT_EQ(X509_REQ_verify(first.get(), X509_REQ_get0_pubkey(first.get())), 1);
        EXPECT_EQ(EVP_PKEY_eq(X509_REQ_get0_pubkey(first.get()), X509_REQ_get0_pubkey(renewal.get())), 1);
        EXPECT_EQ(X509_REQ_verify(renewal.get(), X509_REQ_get0_pubkey(first.get())), 1);
        ASSERT_NO_FATAL_FAILURE(ExpectCommonName(*first, "first-enrollment"));
        ASSERT_NO_FATAL_FAILURE(ExpectCommonName(*renewal, "renewed-enrollment"));
    }
    // ECDSA signatures are randomized: DER equality is not an idempotency test.
}

void VerifySki(const char* reference_path, const char* path)
{
    auto reference = Parse(reference_path);
    ASSERT_NE(reference, nullptr);
    auto* public_key = X509_REQ_get0_pubkey(reference.get());
    ASSERT_NE(public_key, nullptr);
    ASSERT_EQ(X509_REQ_verify(reference.get(), public_key), 1);
    auto* public_key_info = X509_REQ_get_X509_PUBKEY(reference.get());
    ASSERT_NE(public_key_info, nullptr);
    const unsigned char* key_bytes = nullptr;
    int key_size = 0;
    ASSERT_EQ(X509_PUBKEY_get0_param(nullptr, &key_bytes, &key_size, nullptr, public_key_info), 1);
    ASSERT_NE(key_bytes, nullptr);
    ASSERT_GT(key_size, 0);
    std::array<unsigned char, EVP_MAX_MD_SIZE> expected_identifier{};
    unsigned int identifier_size = 0U;
    // OpenSSL's SKI "hash" is SHA-1 over the subjectPublicKey BIT STRING
    // contents, not the full SPKI. CSR signing remains ECDSA/SHA-256.
    ASSERT_EQ(EVP_Digest(key_bytes,
                         static_cast<std::size_t>(key_size),
                         expected_identifier.data(),
                         &identifier_size,
                         EVP_sha1(),
                         nullptr),
              1);
    ASSERT_EQ(identifier_size, 20U);

    auto request = Parse(path);
    ASSERT_NE(request, nullptr);
    auto* embedded_key = X509_REQ_get0_pubkey(request.get());
    ASSERT_NE(embedded_key, nullptr);
    EXPECT_EQ(EVP_PKEY_eq(public_key, embedded_key), 1);
    EXPECT_EQ(X509_REQ_get_version(request.get()), 0L);
    EXPECT_EQ(X509_REQ_get_signature_nid(request.get()), NID_ecdsa_with_SHA256);
    ASSERT_EQ(X509_REQ_verify(request.get(), public_key), 1);
    ASSERT_NO_FATAL_FAILURE(ExpectCommonName(*request, "ski-fallback.example"));

    auto free_extensions = [](STACK_OF(X509_EXTENSION) * value) {
        sk_X509_EXTENSION_pop_free(value, X509_EXTENSION_free);
    };
    std::unique_ptr<STACK_OF(X509_EXTENSION), decltype(free_extensions)> extensions{
        X509_REQ_get_extensions(request.get()), free_extensions};
    ASSERT_NE(extensions, nullptr);
    ASSERT_EQ(sk_X509_EXTENSION_num(extensions.get()), 1);
    auto* extension = sk_X509_EXTENSION_value(extensions.get(), 0);
    ASSERT_NE(extension, nullptr);
    EXPECT_EQ(OBJ_obj2nid(X509_EXTENSION_get_object(extension)), NID_subject_key_identifier);
    EXPECT_EQ(X509_EXTENSION_get_critical(extension), 0);
    std::unique_ptr<ASN1_OCTET_STRING, decltype(&ASN1_OCTET_STRING_free)> identifier{
        static_cast<ASN1_OCTET_STRING*>(X509V3_EXT_d2i(extension)), ASN1_OCTET_STRING_free};
    ASSERT_NE(identifier, nullptr);
    ASSERT_EQ(ASN1_STRING_length(identifier.get()), static_cast<int>(identifier_size));
    const auto* identifier_bytes = ASN1_STRING_get0_data(identifier.get());
    ASSERT_NE(identifier_bytes, nullptr);
    EXPECT_EQ(std::memcmp(identifier_bytes, expected_identifier.data(), identifier_size), 0);
}

void VerifyP384(const char* path)
{
    auto request = Parse(path);
    ASSERT_NE(request, nullptr);
    // Verify proof of possession and the expected P-384/SHA-384 signature algorithm.
    EXPECT_EQ(X509_REQ_get_signature_nid(request.get()), NID_ecdsa_with_SHA384);
    ASSERT_EQ(X509_REQ_verify(request.get(), X509_REQ_get0_pubkey(request.get())), 1);

    const std::string ecu_uid = "ECU-UID:00112233445566778899AABBCCDDEEFF";
    const std::array<std::pair<const char*, std::string>, 7> profile{{{"2.5.4.43", "SCORE"},
                                                                      {"2.5.4.8", "State"},
                                                                      {"2.5.4.7", "Locality"},
                                                                      {"2.5.4.10", "Organization"},
                                                                      {"2.5.4.11", "Enrollment"},
                                                                      {"2.5.4.3", "reference-device"},
                                                                      {"2.5.4.5", ecu_uid}}};
    auto* name = X509_REQ_get_subject_name(request.get());
    ASSERT_NE(name, nullptr);
    ASSERT_EQ(X509_NAME_entry_count(name), static_cast<int>(profile.size()));
    for (std::size_t i = 0; i < profile.size(); ++i)
    {
        auto* entry = X509_NAME_get_entry(name, static_cast<int>(i));
        ASSERT_NE(entry, nullptr);
        std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)> oid{OBJ_txt2obj(profile[i].first, 1),
                                                                      ASN1_OBJECT_free};
        ASSERT_NE(oid, nullptr);
        EXPECT_EQ(OBJ_cmp(X509_NAME_ENTRY_get_object(entry), oid.get()), 0);
        EXPECT_EQ(Text(X509_NAME_ENTRY_get_data(entry)), profile[i].second);
    }

    constexpr const char* kRoleOid = "1.3.6.1.4.1.513.29.10";
    constexpr const char* kTesterOid = "1.3.6.1.4.1.513.29.30";
    const std::array<std::uint8_t, 6> role_mask{{0x04, 0x04, 0x00, 0x00, 0x01, 0x03}};
    const std::array<std::uint8_t, 6> tester{{0x31, 0x04, 0x04, 0x02, 0x0E, 0xFB}};
    auto free_extensions = [](STACK_OF(X509_EXTENSION) * value) {
        sk_X509_EXTENSION_pop_free(value, X509_EXTENSION_free);
    };
    std::unique_ptr<STACK_OF(X509_EXTENSION), decltype(free_extensions)> extensions{
        X509_REQ_get_extensions(request.get()), free_extensions};
    ASSERT_NE(extensions, nullptr);
    ASSERT_EQ(sk_X509_EXTENSION_num(extensions.get()), 2);
    const std::array<std::pair<const char*, const std::array<std::uint8_t, 6>*>, 2> expected{
        {{kRoleOid, &role_mask}, {kTesterOid, &tester}}};
    for (const auto& [oid, bytes] : expected)
    {
        std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)> object{OBJ_txt2obj(oid, 1), ASN1_OBJECT_free};
        ASSERT_NE(object, nullptr);
        const int location = X509v3_get_ext_by_OBJ(extensions.get(), object.get(), -1);
        ASSERT_GE(location, 0);
        auto* extension = sk_X509_EXTENSION_value(extensions.get(), location);
        ASSERT_NE(extension, nullptr);
        EXPECT_EQ(X509_EXTENSION_get_critical(extension), 1);
        const ASN1_OCTET_STRING* data = X509_EXTENSION_get_data(extension);
        ASSERT_NE(data, nullptr);
        ASSERT_EQ(ASN1_STRING_length(data), static_cast<int>(bytes->size()));
        EXPECT_EQ(std::memcmp(ASN1_STRING_get0_data(data), bytes->data(), bytes->size()), 0);
    }
}
}  // namespace

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    if (argc < 3 || argc > 4)
    {
        std::fputs("Expected verifier mode, DER evidence path(s), or P-256 expected CN\n", stderr);
        return 2;
    }
    const std::string_view mode{argv[1]};
    // Direct dispatch deliberately cannot be skipped by an inherited GTEST_FILTER.
    if (mode == "valid" && argc == 3)
    {
        VerifyValid(argv[2]);
    }
    else if (mode == "p256" && argc == 4)
    {
        VerifyP256(argv[2], argv[3]);
    }
    else if (mode == "renewal" && argc == 4)
    {
        VerifyRenewal(argv[2], argv[3], false);
    }
    else if (mode == "persistence" && argc == 4)
    {
        VerifyRenewal(argv[2], argv[3], true);
    }
    else if (mode == "ski" && argc == 4)
    {
        VerifySki(argv[2], argv[3]);
    }
    else if (mode == "p384" && argc == 3)
    {
        VerifyP384(argv[2]);
    }
    else
    {
        std::fputs("Invalid CSR verifier mode or evidence count\n", stderr);
        return 2;
    }
    return ::testing::Test::HasFailure() ? 1 : 0;
}

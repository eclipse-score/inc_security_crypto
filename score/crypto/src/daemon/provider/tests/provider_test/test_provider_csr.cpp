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

#include <gtest/gtest.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>

#include "score/crypto/src/common/csr_der.hpp"
#include "score/crypto/src/common/csr_wire.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/common/context_types.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/i_key_factory.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/csr_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/provider_openssl.hpp"

#include <algorithm>
#include <array>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{
namespace common = score::crypto::daemon::common;
namespace provider = score::crypto::daemon::provider;
namespace km = score::crypto::daemon::key_management;
namespace handler = provider::handler;
namespace csr = handler::csr_handler_operations;
namespace codec = score::crypto::csr::der;
using Bytes = std::vector<std::uint8_t>;
using Error = common::DaemonErrorCode;
using Permission = score::crypto::KeyOperationPermission;
constexpr common::OperationIdentifier kGenerate{common::actors::OP_ACTOR_CSR_HANDLER, csr::CSR_GENERATE};
constexpr common::OperationIdentifier kPublicKeyInfo{common::actors::OP_ACTOR_CSR_HANDLER, csr::CSR_PUBLIC_KEY_INFO};

Bytes EncodeInput(const std::vector<codec::SubjectAttribute>& subject,
                  const std::vector<codec::ExtensionSpec>& extensions = {},
                  std::string_view password = {})
{
    auto encoded = codec::EncodeParameters(subject, extensions, password);
    EXPECT_TRUE(encoded.has_value());
    return encoded.has_value() ? std::move(encoded.value()) : Bytes{};
}

Bytes ExampleInput()
{
    return EncodeInput(
        {{"2.5.4.3", "device.example"}, {"2.5.4.10", "Test organization"}},
        {{"2.5.29.17", false, "DNS:device.example,IP:127.0.0.1"}, {"2.5.29.15", true, "digitalSignature"}},
        "enrollment");
}

Bytes MinimalInput()
{
    return EncodeInput({{"2.5.4.3", "device"}});
}

// Test-only ASN.1 builders deliberately bypass the public encoder's semantic
// checks. Lengths and SET ordering remain canonical unless a test corrupts them.
Bytes Tlv(std::uint8_t tag, const Bytes& value)
{
    Bytes encoded{tag};
    if (value.size() < 128U)
    {
        encoded.push_back(static_cast<std::uint8_t>(value.size()));
    }
    else
    {
        Bytes length;
        for (auto size = value.size(); size != 0U; size >>= 8U)
        {
            length.insert(length.begin(), static_cast<std::uint8_t>(size & 0xFFU));
        }
        encoded.push_back(static_cast<std::uint8_t>(0x80U | length.size()));
        encoded.insert(encoded.end(), length.begin(), length.end());
    }
    encoded.insert(encoded.end(), value.begin(), value.end());
    return encoded;
}

Bytes Join(const std::vector<Bytes>& values)
{
    Bytes joined;
    for (const auto& value : values)
    {
        joined.insert(joined.end(), value.begin(), value.end());
    }
    return joined;
}

Bytes Set(std::vector<Bytes> values)
{
    std::sort(values.begin(), values.end());
    return Tlv(0x31U, Join(values));
}

Bytes Object(std::string_view oid)
{
    std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)> object{OBJ_txt2obj(std::string{oid}.c_str(), 1),
                                                                     ASN1_OBJECT_free};
    EXPECT_NE(object, nullptr);
    if (!object)
    {
        return {};
    }
    const int size = i2d_ASN1_OBJECT(object.get(), nullptr);
    EXPECT_GT(size, 0);
    if (size <= 0)
    {
        return {};
    }
    Bytes encoded(static_cast<std::size_t>(size));
    auto* cursor = encoded.data();
    EXPECT_EQ(i2d_ASN1_OBJECT(object.get(), &cursor), size);
    return encoded;
}

Bytes Text(std::string_view text, std::uint8_t tag = 0x0CU)
{
    return Tlv(tag, Bytes(text.begin(), text.end()));
}

Bytes Name(const std::vector<codec::SubjectAttribute>& subject = {{"2.5.4.3", "device"}},
           std::uint8_t value_tag = 0x0CU)
{
    std::vector<Bytes> rdns;
    for (const auto& entry : subject)
    {
        rdns.push_back(Set({Tlv(0x30U, Join({Object(entry.oid), Text(entry.value, value_tag)}))}));
    }
    return Tlv(0x30U, Join(rdns));
}

Bytes Attribute(std::string_view oid, const std::vector<Bytes>& values)
{
    return Tlv(0x30U, Join({Object(oid), Set(values)}));
}

Bytes Envelope(const Bytes& name, const std::vector<Bytes>& attributes = {})
{
    return Tlv(0x30U, Join({name, Set(attributes)}));
}

Bytes Extension(std::string_view oid, const Bytes& value, bool critical = false)
{
    std::vector<Bytes> fields{Object(oid)};
    if (critical)
    {
        fields.push_back(Tlv(0x01U, {0xFFU}));
    }
    fields.push_back(Tlv(0x04U, value));
    return Tlv(0x30U, Join(fields));
}

Bytes RequestedExtensions(const std::vector<Bytes>& extensions)
{
    return Attribute("1.2.840.113549.1.9.14", {Tlv(0x30U, Join(extensions))});
}

class ProviderCsrTest : public ::testing::Test
{
  protected:
    static void SetUpTestSuite()
    {
        provider_ = std::make_shared<provider::score_provider::openssl::OpenSSL>();
        ASSERT_TRUE(provider_->Initialize(provider::ProviderInitContext{0U, "OPENSSL"}));
        for (const auto* algorithm :
             {"ECDSA-P256", "ECDSA-P384", "ECDSA-P521", "RSA-2048", "RSA-3072", "RSA-4096", "Ed25519"})
        {
            km::KeyGenerationRequest request;
            request.algorithm = score::crypto::GetAlgorithmDescriptor(algorithm).value();
            request.permissions = Permission::kSign;
            auto generated = provider_->GetKeyFactory()->GenerateKey(request);
            ASSERT_TRUE(generated.has_value()) << algorithm;
            keys_.emplace(algorithm, std::move(generated.value()));
        }
    }

    static void TearDownTestSuite()
    {
        keys_.clear();
        provider_->Shutdown();
        provider_.reset();
    }

    static handler::InitializationParams Params(const km::IKeyHandler* key)
    {
        handler::InitializationParams params;
        params.provider_id = provider_->GetProviderId();
        params.bound_key_handler = key;
        params.key_node_id = 1U;
        return params;
    }

    static handler::Handler::Sptr Create(const std::string& algorithm = "ECDSA-P256-SHA256",
                                         const std::string& key = "ECDSA-P256")
    {
        auto result = provider_->GetCryptoHandlerFactory()->CreateHandler(
            std::string{common::context_types::kCsrGeneration},
            score::crypto::GetAlgorithmDescriptor(algorithm).value());
        EXPECT_TRUE(result.has_value());
        if (!result.has_value())
        {
            return nullptr;
        }
        EXPECT_TRUE(result.value()->InitializeContext(Params(keys_.at(key).get())).has_value());
        return result.value();
    }

    static auto Generate(handler::Handler& context, const Bytes& input)
    {
        common::RequestParameters params{score::cpp::span<const std::uint8_t>{input.data(), input.size()}};
        return context.Execute(kGenerate, params);
    }

    static auto GenerateWithOutput(handler::Handler& context, const Bytes& input, score::cpp::span<std::uint8_t> output)
    {
        common::RequestParameters params{score::cpp::span<const std::uint8_t>{input.data(), input.size()}, output};
        return context.Execute(kGenerate, params);
    }

    static std::shared_ptr<provider::IProvider> provider_;
    static std::map<std::string, km::IKeyHandler::Sptr> keys_;
};
std::shared_ptr<provider::IProvider> ProviderCsrTest::provider_;
std::map<std::string, km::IKeyHandler::Sptr> ProviderCsrTest::keys_;

TEST_F(ProviderCsrTest, RegisteredAlgorithmsProduceSelfVerifyingDerWithSubjectExtensionsAndPassword)
{
    std::vector<std::pair<std::string, std::string>> cases{{"ECDSA-P256", "ECDSA-P256-SHA256"},
                                                           {"ECDSA-P384", "ECDSA-P384-SHA384"},
                                                           {"ECDSA-P521", "ECDSA-P521-SHA512"},
                                                           {"Ed25519", "Ed25519"}};
    for (const std::string bits : {"2048", "3072", "4096"})
    {
        for (const std::string digest : {"SHA256", "SHA384", "SHA512"})
        {
            cases.emplace_back("RSA-" + bits, "RSA-PSS-" + bits + "-" + digest);
        }
    }
    for (const auto& [key, algorithm] : cases)
    {
        SCOPED_TRACE(algorithm);
        auto context = Create(algorithm, key);
        ASSERT_NE(context, nullptr);
        auto result = Generate(*context, ExampleInput());
        ASSERT_TRUE(result.has_value());
        ASSERT_EQ(result->size(), 1U);
        const auto* der = std::get_if<common::OwnedBuffer>(&result.value()[0]);
        ASSERT_NE(der, nullptr);
        ASSERT_LE(der->size(), csr::kMaxDerBytes);
        const auto* cursor = der->data();
        std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)> req{
            d2i_X509_REQ(nullptr, &cursor, static_cast<long>(der->size())), X509_REQ_free};
        ASSERT_NE(req, nullptr);
        EXPECT_EQ(cursor, der->data() + der->size());
        EXPECT_EQ(X509_REQ_get_version(req.get()), 0L);
        EXPECT_EQ(X509_REQ_verify(req.get(), X509_REQ_get0_pubkey(req.get())), 1);
        EXPECT_EQ(X509_NAME_entry_count(X509_REQ_get_subject_name(req.get())), 2);
        char cn[64]{};
        ASSERT_GT(X509_NAME_get_text_by_NID(X509_REQ_get_subject_name(req.get()), NID_commonName, cn, sizeof(cn)), 0);
        EXPECT_STREQ(cn, "device.example");
        auto* extensions = X509_REQ_get_extensions(req.get());
        ASSERT_NE(extensions, nullptr);
        ASSERT_EQ(sk_X509_EXTENSION_num(extensions), 2);
        EXPECT_EQ(X509_EXTENSION_get_critical(sk_X509_EXTENSION_value(extensions, 0)), 0);
        EXPECT_EQ(X509_EXTENSION_get_critical(sk_X509_EXTENSION_value(extensions, 1)), 1);
        auto* names = static_cast<GENERAL_NAMES*>(X509V3_EXT_d2i(sk_X509_EXTENSION_value(extensions, 0)));
        ASSERT_NE(names, nullptr);
        EXPECT_EQ(sk_GENERAL_NAME_num(names), 2);
        GENERAL_NAMES_free(names);
        sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
        const int password_index = X509_REQ_get_attr_by_NID(req.get(), NID_pkcs9_challengePassword, -1);
        ASSERT_GE(password_index, 0);
        const auto* password = X509_ATTRIBUTE_get0_type(X509_REQ_get_attr(req.get(), password_index), 0);
        ASSERT_NE(password, nullptr);
        EXPECT_EQ(ASN1_STRING_length(password->value.asn1_string), 10);
        if (algorithm.find("RSA-PSS") == 0U)
        {
            EXPECT_EQ(X509_REQ_get_signature_nid(req.get()), NID_rsassaPss);
            const X509_ALGOR* alg = nullptr;
            const ASN1_BIT_STRING* signature = nullptr;
            X509_REQ_get0_signature(req.get(), &signature, &alg);
            ASSERT_NE(alg, nullptr);
            ASSERT_EQ(alg->parameter->type, V_ASN1_SEQUENCE);
            const auto* p = ASN1_STRING_get0_data(alg->parameter->value.sequence);
            auto* pss = d2i_RSA_PSS_PARAMS(nullptr, &p, ASN1_STRING_length(alg->parameter->value.sequence));
            ASSERT_NE(pss, nullptr);
            ASSERT_NE(pss->saltLength, nullptr);
            const long expected_salt = algorithm.find("SHA256") != std::string::npos   ? 32L
                                       : algorithm.find("SHA384") != std::string::npos ? 48L
                                                                                       : 64L;
            EXPECT_EQ(ASN1_INTEGER_get(pss->saltLength), expected_salt);
            RSA_PSS_PARAMS_free(pss);
        }
        // Every operation is independent; failure or completion leaves it reusable.
        EXPECT_TRUE(Generate(*context, MinimalInput()).has_value());
    }
}

TEST_F(ProviderCsrTest, NativeWireUsesBoundKeyAndRejectsKeyOrMetadataOverridesWithoutOutputMutation)
{
    namespace wire = score::crypto::csr::wire;
    constexpr common::OperationIdentifier native{common::actors::OP_ACTOR_CSR_HANDLER, csr::CSR_GENERATE_NATIVE};
    for (const auto& [key, algorithm] : std::vector<std::pair<std::string, std::string>>{
             {"ECDSA-P256", "ECDSA-P256-SHA256"}, {"RSA-2048", "RSA-PSS-2048-SHA256"}, {"Ed25519", "Ed25519"}})
    {
        auto context = Create(algorithm, key);
        ASSERT_TRUE(context);
        wire::Document input;
        input.action = wire::Action::Generate;
        input.text = "challenge";
        auto subject = std::make_unique<wire::fb::EntryT>();
        subject->oid = "2.5.4.3";
        subject->value = "native-device";
        input.subject.push_back(std::move(subject));
        auto extension = std::make_unique<wire::fb::ExtensionT>();
        extension->oid = "2.5.29.14";
        extension->value = "hash";
        input.extensions.push_back(std::move(extension));
        auto encoded = wire::Encode(input);
        ASSERT_TRUE(encoded.has_value());
        Bytes output(csr::kMaxDerBytes, 0xA5U);
        common::RequestParameters parameters{score::cpp::span<const uint8_t>{encoded->data(), encoded->size()},
                                             score::cpp::span<uint8_t>{output.data(), output.size()}};
        auto generated = context->Execute(native, parameters);
        ASSERT_TRUE(generated.has_value());
        const auto count = std::get<uint64_t>(generated.value()[0]);
        ASSERT_LE(count, output.size());
        const auto* cursor = output.data();
        std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)> request{
            d2i_X509_REQ(nullptr, &cursor, static_cast<long>(count)), X509_REQ_free};
        ASSERT_TRUE(request);
        EXPECT_EQ(cursor, output.data() + count);
        EXPECT_EQ(X509_REQ_verify(request.get(), X509_REQ_get0_pubkey(request.get())), 1);
        for (unsigned mutation = 0U; mutation < 4U; ++mutation)
        {
            auto invalid = input;
            if (mutation == 0U)
            {
                invalid.algorithm = "Ed25519";
            }
            else if (mutation == 1U)
            {
                invalid.bytes = {1U};
            }
            else if (mutation == 2U)
            {
                invalid.resource = "other-key";
            }
            else
            {
                invalid.action = wire::Action::Encode;
            }
            encoded = wire::Encode(invalid);
            ASSERT_TRUE(encoded.has_value());
            std::fill(output.begin(), output.end(), 0xA5U);
            parameters = {score::cpp::span<const uint8_t>{encoded->data(), encoded->size()},
                          score::cpp::span<uint8_t>{output.data(), output.size()}};
            EXPECT_FALSE(context->Execute(native, parameters).has_value());
            EXPECT_TRUE(std::all_of(output.begin(), output.end(), [](uint8_t byte) {
                return byte == 0xA5U;
            }));
        }
    }
}

TEST_F(ProviderCsrTest, WritesVerifiedDerToOutputAndReturnsOnlyByteCount)
{
    const std::vector<std::pair<std::string, std::string>> cases{{"ECDSA-P256", "ECDSA-P256-SHA256"},
                                                                 {"ECDSA-P384", "ECDSA-P384-SHA384"},
                                                                 {"ECDSA-P521", "ECDSA-P521-SHA512"},
                                                                 {"Ed25519", "Ed25519"},
                                                                 {"RSA-2048", "RSA-PSS-2048-SHA256"},
                                                                 {"RSA-3072", "RSA-PSS-3072-SHA384"},
                                                                 {"RSA-4096", "RSA-PSS-4096-SHA512"}};
    for (const auto& [key, algorithm] : cases)
    {
        SCOPED_TRACE(algorithm);
        auto context = Create(algorithm, key);
        ASSERT_NE(context, nullptr);
        // Guards and the unused output tail must not be overwritten.
        std::vector<std::uint8_t> guarded(csr::kMaxDerBytes + 8U, 0xA5U);
        auto result = GenerateWithOutput(*context, ExampleInput(), {guarded.data() + 4U, csr::kMaxDerBytes});
        ASSERT_TRUE(result.has_value());
        ASSERT_EQ(result->size(), 1U);
        const auto* written = std::get_if<std::uint64_t>(&result.value()[0]);
        ASSERT_NE(written, nullptr);  // No DER bytes in the control response.
        ASSERT_GT(*written, 0U);
        ASSERT_LE(*written, csr::kMaxDerBytes);
        const auto* begin = guarded.data() + 4U;
        const auto* cursor = begin;
        std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)> req{
            d2i_X509_REQ(nullptr, &cursor, static_cast<long>(*written)), X509_REQ_free};
        ASSERT_NE(req, nullptr);
        EXPECT_EQ(cursor, begin + *written);
        EXPECT_EQ(X509_REQ_verify(req.get(), X509_REQ_get0_pubkey(req.get())), 1);
        EXPECT_EQ(X509_NAME_entry_count(X509_REQ_get_subject_name(req.get())), 2);
        EXPECT_TRUE(std::all_of(guarded.begin(), guarded.begin() + 4U, [](std::uint8_t byte) {
            return byte == 0xA5U;
        }));
        EXPECT_TRUE(std::all_of(
            guarded.begin() + 4U + static_cast<std::size_t>(*written), guarded.end(), [](std::uint8_t byte) {
                return byte == 0xA5U;
            }));
        EXPECT_TRUE(GenerateWithOutput(*context, MinimalInput(), {guarded.data() + 4U, csr::kMaxDerBytes}).has_value());
    }
}

TEST_F(ProviderCsrTest, BoundPublicKeyInfoReturnsOnlySpkiAndWritesGuardedOutputWithCount)
{
    const std::vector<std::pair<std::string, std::string>> cases{{"ECDSA-P256", "ECDSA-P256-SHA256"},
                                                                 {"ECDSA-P384", "ECDSA-P384-SHA384"},
                                                                 {"ECDSA-P521", "ECDSA-P521-SHA512"},
                                                                 {"Ed25519", "Ed25519"},
                                                                 {"RSA-2048", "RSA-PSS-2048-SHA256"},
                                                                 {"RSA-3072", "RSA-PSS-3072-SHA384"},
                                                                 {"RSA-4096", "RSA-PSS-4096-SHA512"}};
    for (const auto& [key, algorithm] : cases)
    {
        SCOPED_TRACE(algorithm);
        auto context = Create(algorithm, key);
        ASSERT_NE(context, nullptr);
        common::RequestParameters parameters;
        const auto inline_result = context->Execute(kPublicKeyInfo, parameters);
        ASSERT_TRUE(inline_result.has_value());
        ASSERT_EQ(inline_result->size(), 1U);
        const auto* spki = std::get_if<common::OwnedBuffer>(&inline_result.value()[0]);
        ASSERT_NE(spki, nullptr);
        ASSERT_FALSE(spki->empty());
        const auto* cursor = spki->data();
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> public_key{
            d2i_PUBKEY(nullptr, &cursor, static_cast<long>(spki->size())), EVP_PKEY_free};
        ASSERT_NE(public_key, nullptr);
        EXPECT_EQ(cursor, spki->data() + spki->size());

        Bytes guarded(csr::kMaxDerBytes + 8U, 0xA5U);
        parameters = {score::cpp::span<std::uint8_t>{guarded.data() + 4U, csr::kMaxDerBytes}};
        const auto shared = context->Execute(kPublicKeyInfo, parameters);
        ASSERT_TRUE(shared.has_value());
        ASSERT_EQ(shared->size(), 1U);
        const auto* written = std::get_if<std::uint64_t>(&shared.value()[0]);
        ASSERT_NE(written, nullptr);
        ASSERT_EQ(*written, spki->size());
        ASSERT_LE(*written, csr::kMaxDerBytes);
        EXPECT_EQ(Bytes(guarded.begin() + 4U, guarded.begin() + 4U + static_cast<std::size_t>(*written)), *spki);
        EXPECT_TRUE(std::all_of(guarded.begin(), guarded.begin() + 4U, [](std::uint8_t byte) {
            return byte == 0xA5U;
        }));
        EXPECT_TRUE(std::all_of(
            guarded.begin() + 4U + static_cast<std::size_t>(*written), guarded.end(), [](std::uint8_t byte) {
                return byte == 0xA5U;
            }));

        const auto generated = Generate(*context, MinimalInput());
        ASSERT_TRUE(generated.has_value());
        ASSERT_EQ(generated->size(), 1U);
        const auto* request_der = std::get_if<common::OwnedBuffer>(&generated.value()[0]);
        ASSERT_NE(request_der, nullptr);
        cursor = request_der->data();
        std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)> request{
            d2i_X509_REQ(nullptr, &cursor, static_cast<long>(request_der->size())), X509_REQ_free};
        ASSERT_NE(request, nullptr);
        EXPECT_EQ(cursor, request_der->data() + request_der->size());
        EXPECT_EQ(EVP_PKEY_eq(public_key.get(), X509_REQ_get0_pubkey(request.get())), 1);
        EXPECT_EQ(X509_REQ_verify(request.get(), public_key.get()), 1);
        parameters.clear();
        const auto after_generation = context->Execute(kPublicKeyInfo, parameters);
        ASSERT_TRUE(after_generation.has_value());
        ASSERT_EQ(after_generation->size(), 1U);
        const auto* after_spki = std::get_if<common::OwnedBuffer>(&after_generation.value()[0]);
        ASSERT_NE(after_spki, nullptr);
        EXPECT_EQ(*after_spki, *spki);
    }
}

TEST_F(ProviderCsrTest, PublicKeyInfoRejectsShortReadOnlyNullAndWrongOutputsAndRecovers)
{
    auto context = Create();
    ASSERT_NE(context, nullptr);
    common::RequestParameters parameters{std::uint64_t{1U}};
    auto result = context->Execute(kPublicKeyInfo, parameters);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kInvalidDataType);
    const auto input = MinimalInput();
    parameters = {score::cpp::span<const std::uint8_t>{input.data(), input.size()}};
    result = context->Execute(kPublicKeyInfo, parameters);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kInvalidDataType);
    for (const auto output : {score::cpp::span<std::uint8_t>{}, score::cpp::span<std::uint8_t>{nullptr, 1U}})
    {
        parameters = {output};
        result = context->Execute(kPublicKeyInfo, parameters);
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error(), Error::kInsufficientBufferSize);
    }
    std::array<std::uint8_t, 4U> short_output{0xA5U, 0xA5U, 0xA5U, 0xA5U};
    parameters = {score::cpp::span<std::uint8_t>{short_output.data(), short_output.size()}};
    result = context->Execute(kPublicKeyInfo, parameters);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kInsufficientBufferSize);
    EXPECT_TRUE(std::all_of(short_output.begin(), short_output.end(), [](std::uint8_t byte) {
        return byte == 0xA5U;
    }));
    parameters = {common::NoParam{}, common::NoParam{}};
    result = context->Execute(kPublicKeyInfo, parameters);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kInvalidArgument);
    Bytes output(csr::kMaxDerBytes);
    parameters = {score::cpp::span<std::uint8_t>{output.data(), output.size()}};
    EXPECT_TRUE(context->Execute(kPublicKeyInfo, parameters).has_value());
    EXPECT_TRUE(Generate(*context, MinimalInput()).has_value());
}

TEST_F(ProviderCsrTest, RejectsInvalidOrShortOutputWithoutInlineFallbackAndRecovers)
{
    auto context = Create();
    ASSERT_NE(context, nullptr);
    const auto encoded = MinimalInput();
    const auto input = score::cpp::span<const std::uint8_t>{encoded.data(), encoded.size()};
    common::RequestParameters wrong{input, std::uint64_t{1U}};
    auto result = context->Execute(kGenerate, wrong);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kInvalidDataType);
    wrong = {input, input};  // Read-only SHM direction is not a writable output.
    result = context->Execute(kGenerate, wrong);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kInvalidDataType);
    for (const auto output : {score::cpp::span<std::uint8_t>{}, score::cpp::span<std::uint8_t>{nullptr, 1U}})
    {
        result = GenerateWithOutput(*context, encoded, output);
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error(), Error::kInsufficientBufferSize);
    }
    std::array<std::uint8_t, 4U> short_output{0xA5U, 0xA5U, 0xA5U, 0xA5U};
    result = GenerateWithOutput(*context, encoded, short_output);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kInsufficientBufferSize);
    EXPECT_TRUE(std::all_of(short_output.begin(), short_output.end(), [](std::uint8_t byte) {
        return byte == 0xA5U;
    }));
    std::vector<std::uint8_t> output(csr::kMaxDerBytes);
    EXPECT_TRUE(GenerateWithOutput(*context, encoded, output).has_value());
}

TEST_F(ProviderCsrTest, RejectsMalformedAndOversizedDerAndRecovers)
{
    auto context = Create();
    ASSERT_NE(context, nullptr);
    const auto minimal = MinimalInput();
    ASSERT_GE(minimal.size(), 2U);
    ASSERT_LT(minimal[1], 128U);
    auto wrong_tag = minimal;
    wrong_tag[0] = 0x31U;
    auto truncated = minimal;
    truncated.pop_back();
    auto trailing = minimal;
    trailing.push_back(0x00U);
    Bytes indefinite{0x30U, 0x80U};
    indefinite.insert(indefinite.end(), minimal.begin() + 2U, minimal.end());
    indefinite.insert(indefinite.end(), {0x00U, 0x00U});
    Bytes nonminimal{0x30U, 0x81U, minimal[1]};
    nonminimal.insert(nonminimal.end(), minimal.begin() + 2U, minimal.end());
    Bytes leading_zero{0x30U, 0x82U, 0x00U, minimal[1]};
    leading_zero.insert(leading_zero.end(), minimal.begin() + 2U, minimal.end());
    const auto password = Attribute("1.2.840.113549.1.9.7", {Text("enrollment")});
    const auto usage = Extension("2.5.29.15", {0x03U, 0x02U, 0x07U, 0x80U}, true);
    const auto extensions = RequestedExtensions({usage});
    // Prove the handcrafted baseline is the same protocol shape as the shared
    // encoder, rather than letting every semantic case fail on a broken wrapper.
    std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)> fixture{X509_REQ_new(), X509_REQ_free};
    ASSERT_NE(fixture, nullptr);
    const auto baseline = Envelope(Name(), {password, extensions});
    ASSERT_TRUE(codec::PopulateRequest(fixture.get(), {baseline.data(), baseline.size()}).has_value());
    EXPECT_EQ(X509_NAME_entry_count(X509_REQ_get_subject_name(fixture.get())), 1);
    EXPECT_GE(X509_REQ_get_attr_by_NID(fixture.get(), NID_pkcs9_challengePassword, -1), 0);
    EXPECT_GE(X509_REQ_get_attr_by_NID(fixture.get(), NID_ext_req, -1), 0);
    EXPECT_EQ(X509_REQ_get0_pubkey(fixture.get()), nullptr);
    auto other_context = Create("RSA-PSS-2048-SHA256", "RSA-2048");
    ASSERT_NE(other_context, nullptr);
    common::RequestParameters query;
    const auto key_info = other_context->Execute(kPublicKeyInfo, query);
    ASSERT_TRUE(key_info.has_value());
    ASSERT_EQ(key_info->size(), 1U);
    const auto* foreign_spki = std::get_if<common::OwnedBuffer>(&key_info.value()[0]);
    ASSERT_NE(foreign_spki, nullptr);
    auto deep = Text("x");
    for (std::size_t depth = 0U; depth < 20U; ++depth)
    {
        deep = Tlv(0x30U, deep);
    }
    std::vector<codec::SubjectAttribute> too_many_subjects(csr::kMaxSubjectEntries + 1U, {"1.2.3.4", "x"});
    std::vector<Bytes> too_many_extensions;
    for (std::size_t i = 0U; i <= csr::kMaxExtensions; ++i)
    {
        too_many_extensions.push_back(Extension("1.2.3.4." + std::to_string(i + 1U), {0x05U, 0x00U}));
    }
    std::string long_oid = "1.2";
    while (long_oid.size() <= csr::kMaxOidBytes)
    {
        long_oid += ".1";
    }
    const std::vector<std::pair<std::string, Bytes>> invalid{
        {"wrong envelope tag", wrong_tag},
        {"truncated envelope", truncated},
        {"trailing byte", trailing},
        {"indefinite length", indefinite},
        {"nonminimal length", nonminimal},
        {"leading zero length", leading_zero},
        {"empty envelope", Tlv(0x30U, {})},
        {"missing attributes", Tlv(0x30U, Name())},
        {"wrong attributes tag", Tlv(0x30U, Join({Name(), Tlv(0x30U, {})}))},
        {"extra field", Tlv(0x30U, Join({Name(), Set({}), Tlv(0x05U, {})}))},
        {"attempted public key field", Tlv(0x30U, Join({Name(), Set({}), *foreign_spki}))},
        {"attempted algorithm field",
         Tlv(0x30U, Join({Name(), Set({}), Tlv(0x30U, Join({Object("1.2.840.113549.1.1.10"), Tlv(0x05U, {})}))}))},
        {"empty subject", Envelope(Name({}))},
        {"empty subject value", Envelope(Name({{"2.5.4.3", ""}}))},
        {"NUL subject", Envelope(Name({{"2.5.4.3", std::string{"x\0y", 3U}}}))},
        {"invalid UTF-8 subject", Envelope(Name({{"2.5.4.3", std::string{"\xC3\x28", 2U}}}))},
        {"non-string subject", Envelope(Name({{"2.5.4.3", "x"}}, 0x04U))},
        {"malformed subject OID", Envelope(Tlv(0x30U, Set({Tlv(0x30U, Join({Tlv(0x06U, {0x80U}), Text("x")}))})))},
        {"unknown attribute", Envelope(Name(), {Attribute("1.2.3.4", {Text("x")})})},
        {"duplicate password", Envelope(Name(), {password, password})},
        {"duplicate extension request", Envelope(Name(), {extensions, extensions})},
        {"duplicate extension OID", Envelope(Name(), {RequestedExtensions({usage, usage})})},
        {"password with no value", Envelope(Name(), {Attribute("1.2.840.113549.1.9.7", {})})},
        {"password with multiple values",
         Envelope(Name(), {Attribute("1.2.840.113549.1.9.7", {Text("a"), Text("b")})})},
        {"non-string password", Envelope(Name(), {Attribute("1.2.840.113549.1.9.7", {Tlv(0x02U, {1U})})})},
        {"NUL password", Envelope(Name(), {Attribute("1.2.840.113549.1.9.7", {Text(std::string{"x\0y", 3U})})})},
        {"invalid UTF-8 password",
         Envelope(Name(), {Attribute("1.2.840.113549.1.9.7", {Text(std::string{"\xC3\x28", 2U})})})},
        {"wrong extension request type", Envelope(Name(), {Attribute("1.2.840.113549.1.9.14", {Text("x")})})},
        {"invalid critical flag",
         Envelope(
             Name(),
             {RequestedExtensions({Tlv(
                 0x30U, Join({Object("2.5.29.15"), Tlv(0x02U, {1U}), Tlv(0x04U, {0x03U, 0x02U, 0x07U, 0x80U})}))})})},
        {"excessive nesting", Envelope(Name(), {Attribute("1.2.840.113549.1.9.7", {deep})})},
        {"oversized input", Envelope(Name({{"1.2.3.4", std::string(csr::kMaxInputDerBytes + 1U, 'x')}}))},
        {"oversized subject value", Envelope(Name({{"1.2.3.4", std::string(csr::kMaxValueBytes + 1U, 'x')}}))},
        {"oversized OID", Envelope(Name({{long_oid, "x"}}))},
        {"too many subject entries", Envelope(Name(too_many_subjects))},
        {"too many extensions", Envelope(Name(), {RequestedExtensions(too_many_extensions)})},
        {"oversized password",
         Envelope(
             Name(),
             {Attribute("1.2.840.113549.1.9.7", {Text(std::string(csr::kMaxChallengePasswordBytes + 1U, 'x'))})})}};
    for (const auto& [name, encoded] : invalid)
    {
        SCOPED_TRACE(name);
        auto result = Generate(*context, encoded);
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error(), Error::kInvalidArgument);
        std::vector<std::uint8_t> output(csr::kMaxDerBytes, 0xA5U);
        result = GenerateWithOutput(*context, encoded, output);
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error(), Error::kInvalidArgument);
        EXPECT_TRUE(std::all_of(output.begin(), output.end(), [](std::uint8_t byte) {
            return byte == 0xA5U;
        }));
        EXPECT_TRUE(Generate(*context, minimal).has_value());
        EXPECT_TRUE(GenerateWithOutput(*context, minimal, output).has_value());
    }
}

TEST_F(ProviderCsrTest, RetainsOpaqueRawExtensionValuesWithoutInterpretingTheirContents)
{
    auto context = Create();
    ASSERT_NE(context, nullptr);
    // Raw DER escape-hatch inputs have always allowed application-supplied
    // extension octets. The daemon validates the enclosing attributes and
    // extension wrappers; it does not assume the CA's extension-value policy.
    const std::vector<std::pair<std::string, Bytes>> cases{{"2.5.29.15", {0x03U, 0x02U, 0x08U, 0x80U}},
                                                           {"2.5.29.17", {0x30U, 0x02U, 0x82U}}};
    for (const auto& [oid, value] : cases)
    {
        SCOPED_TRACE(oid);
        const auto input = Envelope(Name(), {RequestedExtensions({Extension(oid, value)})});
        for (const bool output_buffer : {false, true})
        {
            SCOPED_TRACE(output_buffer);
            Bytes encoded(csr::kMaxDerBytes);
            auto result = output_buffer ? GenerateWithOutput(*context, input, encoded) : Generate(*context, input);
            ASSERT_TRUE(result.has_value());
            ASSERT_EQ(result->size(), 1U);
            if (output_buffer)
            {
                const auto* count = std::get_if<std::uint64_t>(&result.value()[0]);
                ASSERT_NE(count, nullptr);
                ASSERT_GT(*count, 0U);
                ASSERT_LE(*count, encoded.size());
                encoded.resize(static_cast<std::size_t>(*count));
            }
            else
            {
                const auto* bytes = std::get_if<common::OwnedBuffer>(&result.value()[0]);
                ASSERT_NE(bytes, nullptr);
                encoded = *bytes;
            }
            const auto* cursor = encoded.data();
            std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)> request{
                d2i_X509_REQ(nullptr, &cursor, static_cast<long>(encoded.size())), X509_REQ_free};
            ASSERT_NE(request, nullptr);
            EXPECT_EQ(cursor, encoded.data() + encoded.size());
            EXPECT_EQ(X509_REQ_verify(request.get(), X509_REQ_get0_pubkey(request.get())), 1);
            auto free_extensions = [](STACK_OF(X509_EXTENSION) * extensions) {
                sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
            };
            std::unique_ptr<STACK_OF(X509_EXTENSION), decltype(free_extensions)> extensions{
                X509_REQ_get_extensions(request.get()), free_extensions};
            ASSERT_NE(extensions, nullptr);
            ASSERT_EQ(sk_X509_EXTENSION_num(extensions.get()), 1);
            auto* extension = sk_X509_EXTENSION_value(extensions.get(), 0);
            std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)> expected_oid{OBJ_txt2obj(oid.c_str(), 1),
                                                                                   ASN1_OBJECT_free};
            ASSERT_NE(expected_oid, nullptr);
            EXPECT_EQ(OBJ_cmp(X509_EXTENSION_get_object(extension), expected_oid.get()), 0);
            EXPECT_EQ(X509_EXTENSION_get_critical(extension), 0);
            const auto* octets = X509_EXTENSION_get_data(extension);
            ASSERT_EQ(ASN1_STRING_length(octets), static_cast<int>(value.size()));
            const auto* data = ASN1_STRING_get0_data(octets);
            EXPECT_EQ(Bytes(data, data + value.size()), value);
        }
    }
}

TEST_F(ProviderCsrTest, EncoderRejectsInvalidConfigurationBeforeProducingWireBytes)
{
    const std::vector<codec::SubjectAttribute> subject{{"2.5.4.3", "device"}};
    EXPECT_FALSE(codec::EncodeParameters({{"unknownOid", "x"}}, {}, "").has_value());
    EXPECT_FALSE(codec::EncodeParameters(subject, {{"2.5.29.15", true, "badUsage"}}, "").has_value());
    EXPECT_FALSE(codec::EncodeParameters(subject, {{"2.5.29.17", false, "@missing_section"}}, "").has_value());
    EXPECT_FALSE(codec::EncodeParameters(
                     subject, {{"2.5.29.15", true, "digitalSignature"}, {"2.5.29.15", false, "digitalSignature"}}, "")
                     .has_value());
    EXPECT_FALSE(
        codec::EncodeParameters(subject, {{"2.5.29.17", false, std::string(csr::kMaxValueBytes + 1U, 'x')}}, "")
            .has_value());
    auto context = Create();
    ASSERT_NE(context, nullptr);
    EXPECT_TRUE(Generate(*context, MinimalInput()).has_value());
}

TEST_F(ProviderCsrTest, ValidatesActorActionParameterTypesCountsAndBuffers)
{
    auto context = Create();
    ASSERT_NE(context, nullptr);
    common::RequestParameters empty;
    auto result = context->Execute({common::actors::OP_ACTOR_SIGN_HANDLER, csr::CSR_GENERATE}, empty);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kInvalidOperation);
    result = context->Execute({kGenerate.operationActor, 999U}, empty);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kInvalidOperation);
    result = context->Execute(kGenerate, empty);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kInsufficientParameters);
    const auto encoded = MinimalInput();
    common::RequestParameters wrong{std::string_view{reinterpret_cast<const char*>(encoded.data()), encoded.size()}};
    result = context->Execute(kGenerate, wrong);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kInvalidDataType);
    wrong = {score::cpp::span<const std::uint8_t>{}};
    result = context->Execute(kGenerate, wrong);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kInsufficientBufferSize);
    wrong = {score::cpp::span<const std::uint8_t>{nullptr, 1U}};
    result = context->Execute(kGenerate, wrong);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kInsufficientBufferSize);
    wrong = {common::NoParam{}, common::NoParam{}};
    result = context->Execute(kGenerate, wrong);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kInvalidDataType);
    wrong = {common::NoParam{}, common::NoParam{}, common::NoParam{}};
    result = context->Execute(kGenerate, wrong);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kInvalidArgument);
}

TEST_F(ProviderCsrTest, EnforcesKeyBindingPermissionsAlgorithmAndMessageMode)
{
    auto factory = provider_->GetCryptoHandlerFactory();
    const std::string type{common::context_types::kCsrGeneration};
    const auto hash_algorithm = score::crypto::GetAlgorithmDescriptor("SHA256");
    ASSERT_TRUE(hash_algorithm.has_value());
    EXPECT_FALSE(factory->CreateHandler(type, hash_algorithm.value()).has_value());
    const auto signature_algorithm = score::crypto::GetAlgorithmDescriptor("ECDSA-P256-SHA256");
    ASSERT_TRUE(signature_algorithm.has_value());
    auto created = factory->CreateHandler(type, signature_algorithm.value());
    ASSERT_TRUE(created.has_value());
    auto& context = *created.value();
    EXPECT_FALSE(Generate(context, MinimalInput()).has_value());
    common::RequestParameters public_key_request;
    EXPECT_FALSE(context.Execute(kPublicKeyInfo, public_key_request).has_value());
    EXPECT_FALSE(context.InitializeContext(Params(nullptr)).has_value());
    auto mismatched = context.InitializeContext(Params(keys_.at("RSA-2048").get()));
    ASSERT_FALSE(mismatched.has_value());
    EXPECT_EQ(mismatched.error(), Error::kIncompatibleKeyType);
    auto wrong_provider = Params(keys_.at("ECDSA-P256").get());
    ++wrong_provider.provider_id;
    EXPECT_FALSE(context.InitializeContext(wrong_provider).has_value());
    auto prehashed = Params(keys_.at("ECDSA-P256").get());
    prehashed.context_creation_params.resize(7U);
    prehashed.context_creation_params[6U] = static_cast<std::uint8_t>(score::crypto::SignatureInputMode::kPrehashed);
    EXPECT_FALSE(context.InitializeContext(prehashed).has_value());
    km::KeyGenerationRequest request;
    request.algorithm = score::crypto::GetAlgorithmDescriptor("ECDSA-P256").value();
    request.permissions = Permission::kVerify;
    auto denied_key = provider_->GetKeyFactory()->GenerateKey(request);
    ASSERT_TRUE(denied_key.has_value());
    auto denied = context.InitializeContext(Params(denied_key.value().get()));
    ASSERT_FALSE(denied.has_value());
    EXPECT_EQ(denied.error(), Error::kKeyOperationNotPermitted);
    EXPECT_TRUE(context.InitializeContext(Params(keys_.at("ECDSA-P256").get())).has_value());
    EXPECT_TRUE(Generate(context, MinimalInput()).has_value());
    EXPECT_TRUE(context.Execute(kPublicKeyInfo, public_key_request).has_value());
    // A failed reinitialization must not keep an old usable signing context.
    EXPECT_FALSE(context.InitializeContext(Params(nullptr)).has_value());
    EXPECT_FALSE(Generate(context, MinimalInput()).has_value());
    EXPECT_FALSE(context.Execute(kPublicKeyInfo, public_key_request).has_value());
}

TEST_F(ProviderCsrTest, RetainsDerBoundForInlineAndDataPlaneOutput)
{
    auto context = Create();
    ASSERT_NE(context, nullptr);
    EXPECT_EQ(csr::kMaxDerBytes, 1536U);
    const auto encoded = EncodeInput({{"1.2.3.4", std::string(1500U, 'x')}});
    ASSERT_FALSE(encoded.empty());
    const auto result = Generate(*context, encoded);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kInsufficientBufferSize);
    std::vector<std::uint8_t> output(csr::kMaxDerBytes, 0xA5U);
    const auto shared = GenerateWithOutput(*context, encoded, output);
    ASSERT_FALSE(shared.has_value());
    EXPECT_EQ(shared.error(), Error::kInsufficientBufferSize);
    EXPECT_TRUE(std::all_of(output.begin(), output.end(), [](std::uint8_t byte) {
        return byte == 0xA5U;
    }));
    EXPECT_TRUE(Generate(*context, MinimalInput()).has_value());
}
}  // namespace

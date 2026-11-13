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

// Source: fea_um_crypto_1 ancestor 5e8664e3765f259df3b6e812853f8f96f95c519a.
// Original path: score/tests/integration_tests/score_api_csr_test.cpp.
// Selected generated-key coverage only; configured slots and template profiles
// are excluded. The foreign-client case's two slot loads use the source's
// generated P-256 signing-key pattern instead; its isolation assertions remain.
// Transport test: public factory -> gRPC/SHM -> external daemon -> provider.
// No internal connections, mediator, provider factories or protocol test doubles.
// Cryptographic assertions run in the independent offline CSR DER verifier.
#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/config/csr_generation_context_config.hpp"
#include "score/crypto/src/api/config/key_management_context_config.hpp"
#include "score/crypto/src/api/contexts/i_csr_generation_context.hpp"
#include "score/crypto/src/api/contexts/i_key_management_context.hpp"
#include "score/crypto/src/api/crypto_stack_factory.hpp"
#include "score/crypto/src/api/csr/csr_template.hpp"
#include "score/crypto/src/api/i_crypto_context.hpp"
#include "score/tests/integration_tests/csr_der_test_helper.hpp"

#include <gtest/gtest.h>

#include <spawn.h>
#include <sys/wait.h>

#include <charconv>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

extern char** environ;

namespace
{
using namespace score::crypto;

// Fixed algorithm/identity expectations are intentional test data, not deployment
// policy. Only fixture locations and resource mappings are configurable.
constexpr const char* kSignatureAlgorithm = "ECDSA-P256-SHA256";
constexpr const char* kKeyAlgorithm = "ECDSA-P256";
constexpr std::size_t kMaxDerBytes = test::kMaxCsrDerBytes;
constexpr auto kOperationTimeout = std::chrono::seconds{5};
constexpr const char* kPeerMode = "--reject-foreign-key";

const char* FixtureValue(const char* variable, const char* fallback)
{
    const auto* value = std::getenv(variable);
    return value != nullptr && *value != '\0' ? value : fallback;
}

class Client
{
  public:
    void Open()
    {
        CryptoStackConfig config;
        config.SetConnectionEndpoint(FixtureValue("CSR_TEST_ENDPOINT", "unix:///tmp/crypto_daemon.sock"))
            .SetDefaultOperationTimeout(kOperationTimeout);
        auto created = CreateCryptoStack(config);
        ASSERT_TRUE(created.has_value());
        stack = std::move(created.value());
        auto processing_result = stack->CreateCsrProcessingService();
        ASSERT_TRUE(processing_result.has_value());
        processing = std::move(processing_result.value());
        auto context_result = stack->CreateCryptoContext();
        ASSERT_TRUE(context_result.has_value());
        context = std::move(context_result.value());
        KeyManagementContextConfig key_config;
        key_config.SetProviderType(ProviderType::kSoftware);
        auto keys_result = context->CreateKeyManagementContext(key_config);
        ASSERT_TRUE(keys_result.has_value());
        keys = std::move(keys_result.value());
    }

    score::Result<ICsrGenerationContext::Uptr> Csr(const CryptoResourceId& key)
    {
        CsrGenerationContextConfig config;
        config.SetKey(key).SetAlgorithm(kSignatureAlgorithm).SetProviderType(ProviderType::kSoftware);
        return context->CreateCsrGenerationContext(config);
    }

    ICryptoStack::Uptr stack;
    std::unique_ptr<ICsrProcessingService> processing;
    ICryptoContext::Uptr context;
    IKeyManagementContext::Uptr keys;
};

std::vector<std::uint8_t> ReadCsr(const ICsrExport& exported)
{
    const auto size = exported.GetEncodedCsrLength();
    if (size == 0U || size > kMaxDerBytes)
    {
        ADD_FAILURE() << "Invalid CSR DER length: " << size;
        return {};
    }
    std::vector<std::uint8_t> der(size);
    auto written = exported.GetEncodedCsr(der);
    EXPECT_TRUE(written.has_value());
    if (!written.has_value())
    {
        return {};
    }
    if (written.value() != der.size())
    {
        ADD_FAILURE() << "Incomplete CSR DER export";
        return {};
    }
    return der;
}

void ExpectValidCsr(ICsrGenerationContext& context)
{
    ASSERT_TRUE(context.SetSubjectDn("CN=transport.example,O=SCORE,C=DE").has_value());
    auto exported = context.Generate();
    ASSERT_TRUE(exported.has_value());
    const auto der = ReadCsr(*exported.value());
    ASSERT_FALSE(der.empty());
    ASSERT_NO_FATAL_FAILURE(test::VerifyCsrDer("valid", der));
}

TEST(CsrTransport, GeneratedDaemonKeyRemainsBoundAfterClientReleasesKeyHandle)
{
    Client client;
    ASSERT_NO_FATAL_FAILURE(client.Open());
    GenerateKeyParams params;
    params.SetAlgorithm(kKeyAlgorithm).SetPermissions(KeyOperationPermission::kSign);
    auto key = client.keys->GenerateKey(params);
    ASSERT_TRUE(key.has_value());
    auto context = client.Csr(key.value());
    ASSERT_TRUE(context.has_value());
    ASSERT_TRUE(key.value().Release().has_value());
    ASSERT_TRUE(context.value()->SetSubjectDn("CN=first-enrollment,O=SCORE,C=DE").has_value());
    auto first_export = context.value()->Generate();
    ASSERT_TRUE(first_export.has_value());
    const auto first_der = ReadCsr(*first_export.value());
    ASSERT_FALSE(first_der.empty());
    ASSERT_NO_FATAL_FAILURE(test::VerifyCsrDer("valid", first_der));

    ASSERT_TRUE(context.value()->SetSubjectDn("CN=renewed-enrollment,O=SCORE,C=DE").has_value());
    auto renewal_export = context.value()->Generate();
    ASSERT_TRUE(renewal_export.has_value());
    context.value().reset();  // Export must remain valid after context/key cleanup.
    const auto renewal_der = ReadCsr(*renewal_export.value());
    ASSERT_FALSE(renewal_der.empty());
    ASSERT_NO_FATAL_FAILURE(test::VerifyCsrDer("renewal", first_der, renewal_der));
    // ECDSA signatures are randomized: DER equality is not an idempotency test.
}

TEST(CsrTransport, StandaloneHelpersAndTemplatesUseConnectedDaemon)
{
    Client client;
    ASSERT_NO_FATAL_FAILURE(client.Open());
    auto& processing = *client.processing;
    auto subject = CsrSubject::FromDn(processing, "CN=José-${serial},O=SCORE,C=DE");
    ASSERT_TRUE(subject.has_value());
    EXPECT_FALSE(CsrSubject::FromDn(processing, "CN=malformed,").has_value());
    EXPECT_FALSE(subject->Add(processing, CsrOid::kCommonName, std::string{"\xED\xA0\x80"}).has_value());
    ASSERT_EQ(subject->Attributes().size(), 3U);

    CsrTemplate value;
    value.id = "remote-enrollment-template";
    value.key_resource = "TemplateSigningKey";
    value.algorithm = kSignatureAlgorithm;
    value.subject = std::move(subject.value());
    value.submission_url = "https://ca.example/enroll";
    ASSERT_TRUE(value.issuer.Add(processing, CsrOid::kCommonName, "Template Authority").has_value());
    auto usage = CsrExtension::KeyUsage(processing, {CsrKeyUsage::kDigitalSignature});
    ASSERT_TRUE(usage.has_value());
    value.extensions.push_back(usage.value());

    auto stored = DerCsrTemplateStorage::Save(processing, value);
    ASSERT_TRUE(stored.has_value());
    DerCsrTemplateStorage storage{processing, stored.value()};
    EXPECT_FALSE(storage.Load("wrong-template").has_value());
    auto loaded = storage.Load(value.id);
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(loaded->subject.Attributes()[0].value, "José-${serial}");
    EXPECT_EQ(loaded->issuer.Attributes()[0].value, "Template Authority");
    EXPECT_EQ(loaded->key_resource, value.key_resource);
    EXPECT_EQ(loaded->submission_url, value.submission_url);

    const CsrAttributeRequirements required{{"2.5.4.3", "2.5.4.10"}, {"2.5.4.3"}};
    EXPECT_FALSE(CsrTemplateProcessor::Prepare(processing, loaded.value(), {}, required).has_value());
    auto prepared = CsrTemplateProcessor::Prepare(processing, loaded.value(), {{"serial", "001"}}, required);
    ASSERT_TRUE(prepared.has_value());
    EXPECT_EQ(prepared->request.subject.Attributes()[0].value, "José-001");
    ASSERT_TRUE(prepared->request.Validate(processing).has_value());
    auto parameters = prepared->request.ToDer(processing);
    ASSERT_TRUE(parameters.has_value());
    ASSERT_FALSE(parameters->empty());
    EXPECT_EQ(parameters->front(), 0x30U);
    const std::string bytes{parameters->begin(), parameters->end()};
    EXPECT_EQ(bytes.find("Template Authority"), std::string::npos);

    auto damaged = stored.value();
    damaged.push_back(0U);
    DerCsrTemplateStorage damaged_storage{processing, std::move(damaged)};
    EXPECT_FALSE(damaged_storage.Load(value.id).has_value());
    EXPECT_TRUE(storage.Load(value.id).has_value());
}

TEST(CsrTransport, SubjectKeyIdentifierHashUsesBoundDaemonPublicKeyAfterKeyHandleRelease)
{
    Client client;
    ASSERT_NO_FATAL_FAILURE(client.Open());
    GenerateKeyParams params;
    params.SetAlgorithm(kKeyAlgorithm).SetPermissions(KeyOperationPermission::kSign);
    auto key = client.keys->GenerateKey(params);
    ASSERT_TRUE(key.has_value());
    auto context = client.Csr(key.value());
    ASSERT_TRUE(context.has_value());
    ASSERT_TRUE(key.value().Release().has_value());

    CsrRequest input;
    auto subject = CsrSubject::FromDn(*client.processing, "CN=ski-fallback.example,O=SCORE,C=DE");
    ASSERT_TRUE(subject.has_value());
    input.subject = std::move(subject.value());
    input.extensions.push_back({"2.5.29.14", false, "hash"});
    ASSERT_TRUE(input.Validate(*client.processing).has_value());
    // Explicit key-less daemon encoding still rejects missing key context.
    // Production generation does not fetch SPKI or retry in the client.
    const auto without_public_key = input.ToDer(*client.processing);
    ASSERT_FALSE(without_public_key.has_value());
    EXPECT_EQ(*without_public_key.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kInvalidArgument));
    ASSERT_TRUE(context.value()->SetSubject(input.subject).has_value());

    // Obtain independent public-key evidence through an ordinary signed CSR
    // before adding the key-dependent extension. No key export is requested.
    auto reference_export = context.value()->Generate();
    ASSERT_TRUE(reference_export.has_value());
    const auto reference_der = ReadCsr(*reference_export.value());
    ASSERT_FALSE(reference_der.empty());
    ASSERT_NO_FATAL_FAILURE(test::VerifyCsrDer("valid", reference_der));

    ASSERT_TRUE(context.value()->AddExtension(input.extensions.front()).has_value());
    for (unsigned int generation = 0U; generation < 2U; ++generation)
    {
        SCOPED_TRACE(generation);
        // The daemon derives SKI directly from its authorized bound key.
        auto exported = context.value()->Generate();
        ASSERT_TRUE(exported.has_value());
        const auto der = ReadCsr(*exported.value());
        ASSERT_FALSE(der.empty());
        ASSERT_NO_FATAL_FAILURE(test::VerifyCsrDer("ski", reference_der, der));
    }
}

// End-to-end transport coverage for a generated P-384 key and SHA-384 CSR,
// an ordered seven-attribute subject, and two critical custom DER extensions.
// The signed request is verified against its embedded public key.
// No P-384 fixture slot is required; subject values, OIDs and extension bytes
// are fixed test data, not deployment or authorization policy.
TEST(CsrTransport, GeneratedP384KeyIncludesOrderedSubjectAndCriticalCustomExtensions)
{
    Client client;
    ASSERT_NO_FATAL_FAILURE(client.Open());
    GenerateKeyParams params;
    params.SetAlgorithm("ECDSA-P384").SetPermissions(KeyOperationPermission::kSign);
    auto key = client.keys->GenerateKey(params);
    ASSERT_TRUE(key.has_value());

    CsrGenerationContextConfig config;
    config.SetKey(key.value()).SetAlgorithm("ECDSA-P384-SHA384").SetProviderType(ProviderType::kSoftware);
    auto context = client.context->CreateCsrGenerationContext(config);
    ASSERT_TRUE(context.has_value());

    const std::string ecu_uid = "ECU-UID:00112233445566778899AABBCCDDEEFF";
    const std::array<std::pair<const char*, std::string>, 7> profile{{{"2.5.4.43", "SCORE"},
                                                                      {"2.5.4.8", "State"},
                                                                      {"2.5.4.7", "Locality"},
                                                                      {"2.5.4.10", "Organization"},
                                                                      {"2.5.4.11", "Enrollment"},
                                                                      {"2.5.4.3", "reference-device"},
                                                                      {"2.5.4.5", ecu_uid}}};
    CsrSubject subject;
    for (const auto& [oid, value] : profile)
    {
        ASSERT_TRUE(subject.Add(*client.processing, oid, value).has_value());
    }
    ASSERT_TRUE(context.value()->SetSubject(subject).has_value());

    constexpr const char* kRoleOid = "1.3.6.1.4.1.513.29.10";
    constexpr const char* kTesterOid = "1.3.6.1.4.1.513.29.30";
    const std::array<std::uint8_t, 6> role_mask{{0x04, 0x04, 0x00, 0x00, 0x01, 0x03}};
    const std::array<std::uint8_t, 6> tester{{0x31, 0x04, 0x04, 0x02, 0x0E, 0xFB}};
    auto role = CsrExtension::CustomDer(*client.processing, kRoleOid, role_mask, true);
    auto address = CsrExtension::CustomDer(*client.processing, kTesterOid, tester, true);
    ASSERT_TRUE(role.has_value());
    ASSERT_TRUE(address.has_value());
    ASSERT_TRUE(context.value()->AddExtension(role.value()).has_value());
    ASSERT_TRUE(context.value()->AddExtension(address.value()).has_value());

    auto exported = context.value()->Generate();
    ASSERT_TRUE(exported.has_value());
    const auto der = ReadCsr(*exported.value());
    ASSERT_FALSE(der.empty());
    ASSERT_NO_FATAL_FAILURE(test::VerifyCsrDer("p384", der));
}

void RejectForeignKey(std::uint64_t id, std::uint16_t provider)
{
    Client peer;
    ASSERT_NO_FATAL_FAILURE(peer.Open());
    GenerateKeyParams params;
    params.SetAlgorithm(kKeyAlgorithm).SetPermissions(KeyOperationPermission::kSign);
    auto own_key = peer.keys->GenerateKey(params);
    ASSERT_TRUE(own_key.has_value());
    auto own_context = peer.Csr(own_key.value());
    ASSERT_TRUE(own_context.has_value());
    ASSERT_NO_FATAL_FAILURE(ExpectValidCsr(*own_context.value()));
    CryptoResourceId foreign;
    foreign.id = id;
    foreign.primary_provider = provider;
    foreign.type = ResourceType::kKey;
    foreign.persistence = ResourcePersistence::kEphemeral;
    EXPECT_FALSE(peer.Csr(foreign).has_value());
}

TEST(CsrTransport, SeparateClientCannotUseLiveForeignKeyHandle)
{
    Client owner;
    ASSERT_NO_FATAL_FAILURE(owner.Open());
    GenerateKeyParams params;
    params.SetAlgorithm(kKeyAlgorithm).SetPermissions(KeyOperationPermission::kSign);
    auto key = owner.keys->GenerateKey(params);
    ASSERT_TRUE(key.has_value());
    std::array<std::string, 4> argument_values{{"score_api_csr_test",
                                                kPeerMode,
                                                std::to_string(key.value().Id().id),
                                                std::to_string(key.value().Id().primary_provider)}};
    // Avoid fork() in a process already running gRPC background threads.
    // /proc/self/exe is intentional: this transport target is Linux-only.
    char* arguments[] = {argument_values[0].data(),
                         argument_values[1].data(),
                         argument_values[2].data(),
                         argument_values[3].data(),
                         nullptr};
    pid_t child{};
    ASSERT_EQ(posix_spawn(&child, "/proc/self/exe", nullptr, nullptr, arguments, environ), 0);
    int status = 0;
    pid_t waited{};
    do
    {
        waited = waitpid(child, &status, 0);
    } while (waited == -1 && errno == EINTR);
    ASSERT_EQ(waited, child);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0);
    auto context = owner.Csr(key.value());
    ASSERT_TRUE(context.has_value());
    ASSERT_NO_FATAL_FAILURE(ExpectValidCsr(*context.value()));
}

template <typename Integer>
bool ParseUnsigned(const char* input, Integer& result)
{
    const std::string_view text{input};
    if (text.empty())
    {
        return false;
    }
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), result);
    return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size();
}
}  // namespace

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    if (argc > 1 && std::string_view{argv[1]} == kPeerMode)
    {
        std::uint64_t id{};
        std::uint16_t provider{};
        if (argc != 4 || !ParseUnsigned(argv[2], id) || id == 0U || !ParseUnsigned(argv[3], provider))
        {
            std::fputs("Invalid foreign-key test arguments\n", stderr);
            return 2;
        }
        RejectForeignKey(id, provider);
        return ::testing::Test::HasFailure() ? 1 : 0;
    }
    return RUN_ALL_TESTS();
}

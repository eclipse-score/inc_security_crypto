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

#include "score/crypto/src/api/contexts/i_csr_generation_context.hpp"
#include "score/crypto/src/api/csr/csr_template.hpp"
#include "score/crypto/src/api/src/crypto_context_impl.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/common/context_types.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/i_key_factory.hpp"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/csr_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/handler/src/handler_utils.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/csr/csr_processing.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/provider_openssl.hpp"
#include <gtest/gtest.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <algorithm>
#include <array>
#include <memory>
#include <string>
#include <vector>

namespace score::crypto
{
namespace
{
namespace proto = daemon::control_plane::protocol;
namespace provider = daemon::provider;
namespace csr_operations = provider::handler::csr_handler_operations;
constexpr char kReferenceDeviceSerial[] = "example-device-001";
constexpr std::size_t kMaxTemplateIdBytes = 128U;
constexpr std::size_t kMaxSubmissionUrlBytes = 2048U;
NativeCsrProcessing processing;  // Explicit stateless daemon-side helper test adapter.

// In-process protocol bridge: real public API, real provider-generated keys,
// real CSR handler and DER. Does not replace socket/SHM integration testing.
class ProviderConnection final : public api::control_plane::IConnection
{
  public:
    ProviderConnection(std::shared_ptr<provider::IProvider> backend, daemon::key_management::IKeyHandler::Sptr key)
        : backend_{std::move(backend)}, key_{std::move(key)}
    {
    }
    Expected<proto::ControlResponse, CryptoErrorCode> SendRequest(const proto::ControlRequest& request) override
    {
        const auto& operation = request.operation.operations.at(0U);
        proto::SingleOperationResponse output{operation.operationId, proto::OPERATION_RESULT_SUCCESS, {}};
        if (operation.operationId.operationActor == daemon::mediator::operations::CreateContext().operationActor &&
            operation.operationId.operationAction == daemon::mediator::operations::CreateContext().operationAction)
        {
            ++creates;
            EXPECT_EQ(std::get<uint64_t>(operation.parameters.at(3U)), 17U);
            const auto descriptor = GetAlgorithmDescriptor(std::get<std::string_view>(operation.parameters.at(1U)));
            if (!descriptor.has_value())
            {
                return make_unexpected(CryptoErrorCode::kUnsupportedAlgorithm);
            }
            auto created = backend_->GetCryptoHandlerFactory()->CreateHandler(
                std::string{std::get<std::string_view>(operation.parameters.at(0U))}, descriptor.value());
            if (!created.has_value())
            {
                return make_unexpected(CryptoErrorCode::kUnsupportedAlgorithm);
            }
            handler_ = std::move(created.value());
            provider::handler::InitializationParams params;
            params.bound_key_handler = key_.get();
            params.key_node_id = 17U;
            params.provider_id = backend_->GetProviderId();
            params.context_creation_params = operation.parameters;
            if (!handler_->InitializeContext(params).has_value())
            {
                return make_unexpected(CryptoErrorCode::kContextCreationFailed);
            }
            output.parameters.emplace_back(uint64_t{42U});
        }
        else if (operation.operationId.operationAction == daemon::mediator::operations::CSR_PROCESS &&
                 operation.operationId.operationActor == daemon::common::actors::OP_ACTOR_MEDIATOR)
        {
            auto parameters = operation.parameters;
            auto input = provider::handler::handler_utils::CheckAndGetSpan<const uint8_t>(parameters.at(0));
            if (!input.has_value())
            {
                return make_unexpected(CryptoErrorCode::kInvalidArgument);
            }
            auto decoded = score::crypto::csr::wire::Decode(input.value());
            if (!decoded.has_value())
            {
                return make_unexpected(CryptoErrorCode::kInvalidArgument);
            }
            auto result = processing.Process(decoded.value());
            if (!result.has_value())
            {
                output.result = static_cast<proto::OperationResult>(*result.error());
            }
            else
            {
                auto encoded = score::crypto::csr::wire::Encode(result.value());
                if (!encoded.has_value())
                {
                    return make_unexpected(CryptoErrorCode::kInvalidArgument);
                }
                output.parameters.emplace_back(std::move(encoded.value()));
            }
        }
        else if (operation.operationId.operationActor == daemon::common::actors::OP_ACTOR_CSR_HANDLER)
        {
            if (operation.operationId.operationAction == csr_operations::CSR_GENERATE_NATIVE)
            {
                ++generates;
            }
            if (operation.operationId.operationAction == csr_operations::CSR_PUBLIC_KEY_INFO)
            {
                ++public_key_queries;
            }
            auto parameters = operation.parameters;
            auto generated = handler_->Execute(operation.operationId, parameters);
            EXPECT_TRUE(generated.has_value())
                << "CSR provider failure: " << ERR_error_string(ERR_peek_last_error(), nullptr);
            if (!generated.has_value())
            {
                return make_unexpected(CryptoErrorCode::kOperationFailed);
            }
            if (operation.operationId.operationAction == csr_operations::CSR_PUBLIC_KEY_INFO)
            {
                EXPECT_EQ(generated->size(), 1U);
                if (generated->size() == 1U)
                {
                    const auto* spki = std::get_if<daemon::common::OwnedBuffer>(&generated.value()[0]);
                    EXPECT_NE(spki, nullptr);
                    if (spki != nullptr)
                    {
                        public_key_info = *spki;
                    }
                }
            }
            output.parameters = std::move(generated.value());
        }
        else
        {
            ++closes;
            handler_.reset();
        }
        proto::ControlResponse response;
        response.operation.operations.push_back(std::move(output));
        return response;
    }
    proto::DataNodeId GetConnectionNodeId() const override
    {
        return 1U;
    }
    unsigned creates{0U};
    unsigned generates{0U};
    unsigned public_key_queries{0U};
    unsigned closes{0U};
    std::vector<uint8_t> public_key_info;

  private:
    std::shared_ptr<provider::IProvider> backend_;
    daemon::key_management::IKeyHandler::Sptr key_;
    provider::handler::Handler::Sptr handler_;
};

class InputTranscoder final : public IBufferTranscoder
{
  public:
    // This in-process bridge deliberately retains inline provider coverage.
    // Real shared-memory descriptors and output counts are exercised by the
    // context unit test and the external-daemon transport integration test.
    Expected<TranscoderSpan, score::result::Error> Acquire(score::cpp::span<const uint8_t> data,
                                                           bool output = false) override
    {
        if (!output)
        {
            data_ = data;
        }
        TranscoderSpan token;
        token.set_caller_span({const_cast<uint8_t*>(data.data()), data.size()});
        return token;
    }
    Expected<TranscoderSpan, score::result::Error> AcquireInputShm(score::cpp::span<const uint8_t> data) override
    {
        // Production forces SHM even for small DER envelopes; this bridge
        // intentionally exercises the provider's one-input/inline-output form.
        return Acquire(data, false);
    }
    void AppendInputBuffer(proto::OperationRequestBuilder& builder, TranscoderSpan&) override
    {
        builder.with_in_data_buffer(data_);
    }
    void AppendOutputBuffer(proto::OperationRequestBuilder&, TranscoderSpan&) override {}
    score::Result<std::size_t> ExtractOutputBuffer(TranscoderSpan& token,
                                                   proto::ControlResponseValidator& validator,
                                                   std::size_t param_idx) override
    {
        const auto der = validator.getParameterAt<proto::DataBufferReturn>(0U, param_idx);
        if (!der.has_value())
        {
            return score::Unexpected{MakeError(CryptoErrorCode::kOperationFailed, "invalid DER response")};
        }
        if (der->size() > token.caller_span().size())
        {
            return score::Unexpected{MakeError(CryptoErrorCode::kInsufficientBufferSize, "DER buffer too small")};
        }
        std::copy(der->begin(), der->end(), token.caller_span().begin());
        return der->size();
    }

  private:
    score::cpp::span<const uint8_t> data_;
};

class KeyResolver final : public ICsrKeyResolver
{
  public:
    explicit KeyResolver(ResourceId resource = "EnrollmentKey") : resource_{std::move(resource)} {}
    score::Result<CryptoResourceId> ResolveSigningKey(const ResourceId& resource) override
    {
        ++calls;
        last_resource = resource;
        if (resource != resource_)
        {
            return score::Unexpected{MakeError(CryptoErrorCode::kInvalidResourceId, "Unknown key")};
        }
        CryptoResourceId key;
        key.id = 17U;
        key.type = ResourceType::kKey;
        return key;
    }
    unsigned calls{0U};
    ResourceId last_resource;

  private:
    ResourceId resource_;
};

class CsrApiProviderTest : public ::testing::Test
{
  protected:
    static void SetUpTestSuite()
    {
        backend = std::make_shared<provider::score_provider::openssl::OpenSSL>();
        ASSERT_TRUE(backend->Initialize(provider::ProviderInitContext{0U, "OPENSSL"}));
    }
    // Shutdown performs irreversible process-global OpenSSL cleanup. Keep the
    // provider alive across every test in this suite.
    static void TearDownTestSuite()
    {
        backend->Shutdown();
        backend.reset();
    }
    std::shared_ptr<ProviderConnection> Connection(const char* algorithm)
    {
        const auto descriptor = GetAlgorithmDescriptor(algorithm);
        EXPECT_TRUE(descriptor.has_value()) << algorithm;
        if (!descriptor.has_value())
        {
            return nullptr;
        }
        daemon::key_management::KeyGenerationRequest request;
        request.algorithm = descriptor.value();
        request.permissions = KeyOperationPermission::kSign;
        auto key = backend->GetKeyFactory()->GenerateKey(request);
        EXPECT_TRUE(key.has_value());
        return key.has_value() ? std::make_shared<ProviderConnection>(backend, key.value()) : nullptr;
    }
    static std::vector<uint8_t> Der(const ICsrExport& csr)
    {
        std::vector<uint8_t> der(csr.GetEncodedCsrLength());
        EXPECT_TRUE(csr.GetEncodedCsr(der).has_value());
        return der;
    }
    static std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)> Parse(const std::vector<uint8_t>& der)
    {
        const auto* cursor = der.data();
        std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)> req{
            d2i_X509_REQ(nullptr, &cursor, static_cast<long>(der.size())), X509_REQ_free};
        EXPECT_EQ(cursor, der.data() + der.size());
        return req;
    }
    static CsrAttributeRequirements ReferenceRequirements()
    {
        return {{"2.5.4.43", "2.5.4.8", "2.5.4.7", "2.5.4.10", "2.5.4.11", "2.5.4.3", "2.5.4.5"},
                {"2.5.4.6", "2.5.4.10", "2.5.4.11", "2.5.4.8", "2.5.4.3"}};
    }
    static CsrTemplate ReferenceProfile()
    {
        CsrTemplate value;
        // The template id is opaque application metadata, independent of the
        // signing-key resource and any certificate-slot mapping.
        value.id = "example-enrollment";
        value.key_resource = "ApplicationSigningKey";
        value.algorithm = "ECDSA-P256-SHA256";
        value.submission_url = "https://ca.example/enroll";
        EXPECT_TRUE(value.subject.Add(processing, CsrOid::kInitials, "EX").has_value());
        EXPECT_TRUE(value.subject.Add(processing, CsrOid::kState, "Example State").has_value());
        EXPECT_TRUE(value.subject.Add(processing, CsrOid::kLocality, "Example City").has_value());
        EXPECT_TRUE(value.subject.Add(processing, CsrOid::kOrganization, "Example Organization").has_value());
        EXPECT_TRUE(value.subject.Add(processing, CsrOid::kOrganizationalUnit, "Enrollment").has_value());
        EXPECT_TRUE(value.subject.Add(processing, CsrOid::kCommonName, "Example Device").has_value());
        EXPECT_TRUE(value.subject.Add(processing, CsrOid::kSerialNumber, "${DeviceId}").has_value());
        EXPECT_TRUE(value.issuer.Add(processing, CsrOid::kCountry, "DE").has_value());
        EXPECT_TRUE(value.issuer.Add(processing, CsrOid::kOrganization, "Enrollment Authority").has_value());
        EXPECT_TRUE(value.issuer.Add(processing, CsrOid::kOrganizationalUnit, "Issuing Authority").has_value());
        EXPECT_TRUE(value.issuer.Add(processing, CsrOid::kState, "Issuer State").has_value());
        EXPECT_TRUE(value.issuer.Add(processing, CsrOid::kCommonName, "Example Test CA").has_value());
        return value;
    }
    static void ExpectName(X509_NAME* name, const CsrSubject& expected)
    {
        ASSERT_NE(name, nullptr);
        ASSERT_EQ(X509_NAME_entry_count(name), static_cast<int>(expected.Attributes().size()));
        for (std::size_t i = 0; i < expected.Attributes().size(); ++i)
        {
            SCOPED_TRACE(i);
            auto* entry = X509_NAME_get_entry(name, static_cast<int>(i));
            ASSERT_NE(entry, nullptr);
            char oid[80]{};
            ASSERT_GT(OBJ_obj2txt(oid, sizeof(oid), X509_NAME_ENTRY_get_object(entry), 1), 0);
            EXPECT_EQ(std::string{oid}, expected.Attributes()[i].oid);
            const auto* text = X509_NAME_ENTRY_get_data(entry);
            EXPECT_EQ(std::string(reinterpret_cast<const char*>(ASN1_STRING_get0_data(text)),
                                  static_cast<std::size_t>(ASN1_STRING_length(text))),
                      expected.Attributes()[i].value);
            EXPECT_EQ(X509_NAME_ENTRY_set(entry), static_cast<int>(i));
        }
    }
    static std::shared_ptr<provider::IProvider> backend;
};

std::shared_ptr<provider::IProvider> CsrApiProviderTest::backend;

TEST_F(CsrApiProviderTest, PublicApiSignsEcdsaRsaPssAndEd25519WithProviderOwnedKeys)
{
    const std::array<std::pair<const char*, const char*>, 3> algorithms{
        {{"ECDSA-P256", "ECDSA-P256-SHA256"}, {"RSA-2048", "RSA-PSS-2048-SHA256"}, {"Ed25519", "Ed25519"}}};
    for (const auto& [key_algorithm, signature_algorithm] : algorithms)
    {
        SCOPED_TRACE(signature_algorithm);
        auto connection = Connection(key_algorithm);
        ASSERT_NE(connection, nullptr);
        CryptoContextImpl factory{connection, std::make_shared<InputTranscoder>()};
        KeyResolver keys;
        auto key = keys.ResolveSigningKey("EnrollmentKey");
        ASSERT_TRUE(key.has_value());
        CsrGenerationContextConfig config;
        config.SetKey(key.value()).SetAlgorithm(signature_algorithm);
        auto context = factory.CreateCsrGenerationContext(config);
        ASSERT_TRUE(context.has_value());
        ASSERT_TRUE(context.value()->SetSubjectDn("CN=device.example,O=Example,C=DE").has_value());
        ASSERT_TRUE(context.value()->SetChallengePassword("enrollment").has_value());
        auto exported = context.value()->Generate();
        ASSERT_TRUE(exported.has_value());
        auto req = Parse(Der(*exported.value()));
        ASSERT_NE(req, nullptr);
        EXPECT_EQ(X509_REQ_verify(req.get(), X509_REQ_get0_pubkey(req.get())), 1);
        EXPECT_GE(X509_REQ_get_attr_by_NID(req.get(), NID_pkcs9_challengePassword, -1), 0);
        if (std::string_view{key_algorithm} == "RSA-2048")
        {
            EXPECT_EQ(X509_REQ_get_signature_nid(req.get()), NID_rsassaPss);
        }
    }
}

TEST_F(CsrApiProviderTest, SubjectKeyIdentifierHashUsesBoundKeyWithoutClientSpkiQuery)
{
    const std::array<std::pair<const char*, const char*>, 3> algorithms{
        {{"ECDSA-P256", "ECDSA-P256-SHA256"}, {"RSA-2048", "RSA-PSS-2048-SHA256"}, {"Ed25519", "Ed25519"}}};
    for (const auto& [key_algorithm, signature_algorithm] : algorithms)
    {
        SCOPED_TRACE(signature_algorithm);
        auto connection = Connection(key_algorithm);
        ASSERT_NE(connection, nullptr);
        CryptoContextImpl factory{connection, std::make_shared<InputTranscoder>()};
        KeyResolver keys;
        const auto key = keys.ResolveSigningKey("EnrollmentKey");
        ASSERT_TRUE(key.has_value());
        CsrGenerationContextConfig config;
        config.SetKey(key.value()).SetAlgorithm(signature_algorithm);
        auto context = factory.CreateCsrGenerationContext(config);
        ASSERT_TRUE(context.has_value());

        CsrRequest request;
        ASSERT_TRUE(request.subject.Add(processing, CsrOid::kCommonName, "bound-key.example").has_value());
        request.extensions.push_back({"2.5.29.14", false, "hash"});
        // Structural validation must not need a key or reject a valid
        // context-dependent extension. Actual encoding requires the bound SPKI.
        ASSERT_TRUE(request.Validate(processing).has_value());
        EXPECT_FALSE(request.ToDer(processing).has_value());
        EXPECT_EQ(connection->public_key_queries, 0U);
        EXPECT_EQ(connection->generates, 0U);
        ASSERT_TRUE(context.value()->SetSubject(request.subject).has_value());
        ASSERT_TRUE(context.value()->AddExtension(request.extensions[0]).has_value());
        EXPECT_EQ(connection->public_key_queries, 0U);
        EXPECT_EQ(connection->generates, 0U);

        auto exported = context.value()->Generate();
        ASSERT_TRUE(exported.has_value());
        EXPECT_EQ(connection->creates, 1U);
        EXPECT_EQ(connection->public_key_queries, 0U);
        EXPECT_EQ(connection->generates, 1U);
        EXPECT_TRUE(connection->public_key_info.empty());
        auto req = Parse(Der(*exported.value()));
        ASSERT_NE(req, nullptr);
        ASSERT_EQ(X509_REQ_verify(req.get(), X509_REQ_get0_pubkey(req.get())), 1);

        const int spki_size = i2d_PUBKEY(X509_REQ_get0_pubkey(req.get()), nullptr);
        ASSERT_GT(spki_size, 0);
        std::vector<uint8_t> generated_spki(static_cast<std::size_t>(spki_size));
        auto* write = generated_spki.data();
        ASSERT_EQ(i2d_PUBKEY(X509_REQ_get0_pubkey(req.get()), &write), spki_size);
        EXPECT_TRUE(request.ToDer(processing, generated_spki).has_value());
        const auto* read = generated_spki.data();
        std::unique_ptr<X509_PUBKEY, decltype(&X509_PUBKEY_free)> bound_spki{
            d2i_X509_PUBKEY(nullptr, &read, static_cast<long>(generated_spki.size())), X509_PUBKEY_free};
        ASSERT_NE(bound_spki, nullptr);
        EXPECT_EQ(read, generated_spki.data() + generated_spki.size());
        const unsigned char* key_bits = nullptr;
        int key_bits_size = 0;
        ASSERT_EQ(X509_PUBKEY_get0_param(nullptr, &key_bits, &key_bits_size, nullptr, bound_spki.get()), 1);
        ASSERT_NE(key_bits, nullptr);
        ASSERT_GT(key_bits_size, 0);
        std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
        unsigned int digest_size = 0U;
        // The standard SKI hash covers subjectPublicKey BIT STRING contents,
        // not the full SubjectPublicKeyInfo (nor any private-key bytes).
        ASSERT_EQ(
            EVP_Digest(
                key_bits, static_cast<std::size_t>(key_bits_size), digest.data(), &digest_size, EVP_sha1(), nullptr),
            1);
        ASSERT_EQ(digest_size, 20U);
        auto free_extensions = [](STACK_OF(X509_EXTENSION) * extensions) {
            sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
        };
        std::unique_ptr<STACK_OF(X509_EXTENSION), decltype(free_extensions)> extensions{
            X509_REQ_get_extensions(req.get()), free_extensions};
        ASSERT_NE(extensions, nullptr);
        ASSERT_EQ(sk_X509_EXTENSION_num(extensions.get()), 1);
        auto* extension = sk_X509_EXTENSION_value(extensions.get(), 0);
        EXPECT_EQ(OBJ_obj2nid(X509_EXTENSION_get_object(extension)), NID_subject_key_identifier);
        EXPECT_EQ(X509_EXTENSION_get_critical(extension), 0);
        std::unique_ptr<ASN1_OCTET_STRING, decltype(&ASN1_OCTET_STRING_free)> identifier{
            static_cast<ASN1_OCTET_STRING*>(X509V3_EXT_d2i(extension)), ASN1_OCTET_STRING_free};
        ASSERT_NE(identifier, nullptr);
        ASSERT_EQ(ASN1_STRING_length(identifier.get()), static_cast<int>(digest_size));
        const auto* identifier_bytes = ASN1_STRING_get0_data(identifier.get());
        EXPECT_EQ(std::vector<uint8_t>(identifier_bytes, identifier_bytes + digest_size),
                  std::vector<uint8_t>(digest.begin(), digest.begin() + digest_size));
        context.value().reset();
        EXPECT_EQ(connection->closes, 1U);
    }
}

TEST_F(CsrApiProviderTest, StoredTemplateSubstitutionRequirementsExtensionsAndBatchUseThePublicApi)
{
    CsrTemplate value;
    value.id = "device-enrollment";
    value.key_resource = "EnrollmentKey";
    value.algorithm = "ECDSA-P256-SHA256";
    value.submission_url = "https://ca.example/enroll";
    ASSERT_TRUE(value.subject.Add(processing, CsrOid::kCommonName, "device-${serial}").has_value());
    ASSERT_TRUE(value.subject.Add(processing, CsrOid::kSerialNumber, "${serial}").has_value());
    ASSERT_TRUE(value.issuer.Add(processing, CsrOid::kCommonName, "${issuer}").has_value());
    auto san = CsrExtension::SubjectAltNames(processing,
                                             {{CsrSanType::kDns, "device.example"},
                                              {CsrSanType::kIp, "127.0.0.1"},
                                              {CsrSanType::kEmail, "user@example.com"},
                                              {CsrSanType::kUri, "https://example.com/device"}});
    auto usage = CsrExtension::KeyUsage(processing, {CsrKeyUsage::kDigitalSignature});
    auto eku = CsrExtension::ExtendedKeyUsage(processing, {"1.3.6.1.5.5.7.3.2"});
    auto constraints = CsrExtension::BasicConstraints(processing, false);
    const std::array<uint8_t, 4> custom_value{0x04, 0x02, 0xAB, 0xCD};
    auto custom = CsrExtension::CustomDer(processing, "1.2.3.4.5", custom_value, true);
    ASSERT_TRUE(san.has_value());
    ASSERT_TRUE(usage.has_value());
    ASSERT_TRUE(eku.has_value());
    ASSERT_TRUE(constraints.has_value());
    ASSERT_TRUE(custom.has_value());
    value.extensions = {san.value(), usage.value(), eku.value(), constraints.value(), custom.value()};
    auto document = DerCsrTemplateStorage::Save(processing, value);
    ASSERT_TRUE(document.has_value());
    DerCsrTemplateStorage storage{processing, document.value()};
    auto loaded = storage.Load(value.id);
    ASSERT_TRUE(loaded.has_value()) << "template DER bytes: " << document->size();
    CsrAttributeRequirements required{{"2.5.4.3", "2.5.4.5"}, {"2.5.4.3"}};
    auto prepared =
        CsrTemplateProcessor::Prepare(processing, loaded.value(), {{"serial", "123"}, {"issuer", "Root CA"}}, required);
    ASSERT_TRUE(prepared.has_value());
    EXPECT_EQ(prepared->issuer.Attributes()[0].value, "Root CA");
    const auto request_der = prepared->request.ToDer(processing);
    ASSERT_TRUE(request_der.has_value());
    const std::string request_bytes(request_der->begin(), request_der->end());
    EXPECT_EQ(request_bytes.find("Root CA"), std::string::npos);
    auto connection = Connection("ECDSA-P256");
    ASSERT_NE(connection, nullptr);
    CryptoContextImpl factory{connection, std::make_shared<InputTranscoder>()};
    KeyResolver keys;
    auto missing = prepared.value();
    missing.key_resource = "MissingKey";
    auto batch =
        CsrTemplateProcessor::GenerateBatch(processing, {prepared.value(), missing, prepared.value()}, factory, keys);
    ASSERT_EQ(batch.size(), 3U);
    ASSERT_TRUE(batch[0].has_value());
    EXPECT_FALSE(batch[1].has_value());
    ASSERT_TRUE(batch[2].has_value());
    EXPECT_EQ(connection->creates, 2U);
    EXPECT_EQ(connection->generates, 2U);
    EXPECT_EQ(connection->public_key_queries, 0U);
    EXPECT_EQ(connection->closes, 2U);
    EXPECT_EQ(keys.calls, 3U);
    auto req = Parse(Der(*batch[0]->csr));
    ASSERT_NE(req, nullptr);
    EXPECT_EQ(X509_REQ_verify(req.get(), X509_REQ_get0_pubkey(req.get())), 1);
    char cn[64]{};
    ASSERT_GT(X509_NAME_get_text_by_NID(X509_REQ_get_subject_name(req.get()), NID_commonName, cn, sizeof(cn)), 0);
    EXPECT_STREQ(cn, "device-123");
    auto* extensions = X509_REQ_get_extensions(req.get());
    ASSERT_NE(extensions, nullptr);
    ASSERT_EQ(sk_X509_EXTENSION_num(extensions), 5);
    auto* names = static_cast<GENERAL_NAMES*>(X509V3_EXT_d2i(sk_X509_EXTENSION_value(extensions, 0)));
    ASSERT_NE(names, nullptr);
    EXPECT_EQ(sk_GENERAL_NAME_num(names), 4);
    GENERAL_NAMES_free(names);
    const auto* custom_extension = sk_X509_EXTENSION_value(extensions, 4);
    EXPECT_EQ(X509_EXTENSION_get_critical(custom_extension), 1);
    const auto* bytes = X509_EXTENSION_get_data(const_cast<X509_EXTENSION*>(custom_extension));
    ASSERT_EQ(ASN1_STRING_length(bytes), 4);
    EXPECT_EQ(std::vector<uint8_t>(ASN1_STRING_get0_data(bytes), ASN1_STRING_get0_data(bytes) + 4),
              std::vector<uint8_t>(custom_value.begin(), custom_value.end()));
    sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
}

TEST_F(CsrApiProviderTest, CallerBuiltPreparedTemplatesRejectMalformedInputsBeforeSideEffectsAndRecover)
{
    PreparedCsrTemplate valid;
    // Generic IDs remain valid: this is not a UUID or component-profile boundary.
    valid.id = "generic-enrollment";
    valid.key_resource = "EnrollmentKey";
    valid.algorithm = "ECDSA-P256-SHA256";
    valid.submission_url = "https://ca.example/enroll";
    ASSERT_TRUE(valid.request.subject.Add(processing, CsrOid::kCommonName, "device.example").has_value());
    ASSERT_TRUE(valid.request.Validate(processing).has_value());

    std::vector<std::pair<const char*, PreparedCsrTemplate>> malformed;
    const auto add = [&](const char* name, auto mutate) {
        auto value = valid;
        mutate(value);
        malformed.emplace_back(name, std::move(value));
    };
    add("empty id", [](auto& value) {
        value.id.clear();
    });
    add("oversized id", [](auto& value) {
        value.id = std::string(kMaxTemplateIdBytes + 1U, 'i');
    });
    add("NUL id", [](auto& value) {
        value.id += '\0';
        value.id += "suffix";
    });
    add("empty resource", [](auto& value) {
        value.key_resource = "";
    });
    add("truncated resource", [](auto& value) {
        value.key_resource = std::string(ResourceId::max_capacity + 1U, 'r');
    });
    add("NUL resource", [](auto& value) {
        value.key_resource = std::string{"EnrollmentKey"} + '\0' + "suffix";
    });
    add("empty algorithm", [](auto& value) {
        value.algorithm = "";
    });
    add("truncated algorithm", [](auto& value) {
        value.algorithm = std::string(AlgorithmId::max_capacity + 1U, 'a');
    });
    add("NUL algorithm", [](auto& value) {
        value.algorithm = std::string{"ECDSA-P256-SHA256"} + '\0' + "suffix";
    });
    add("oversized URL", [](auto& value) {
        value.submission_url = std::string(kMaxSubmissionUrlBytes + 1U, 'u');
    });
    add("NUL URL", [](auto& value) {
        value.submission_url += '\0';
        value.submission_url += "suffix";
    });
    add("unresolved extension placeholder", [](auto& value) {
        value.request.extensions.push_back({"2.5.29.17", false, "DNS:${hostname}"});
    });

    // The placeholder is otherwise a valid request, and Prepare rejects it too.
    CsrTemplate unprepared;
    unprepared.id = valid.id;
    unprepared.key_resource = valid.key_resource;
    unprepared.algorithm = valid.algorithm;
    unprepared.subject = valid.request.subject;
    unprepared.submission_url = valid.submission_url;
    unprepared.extensions = malformed.back().second.request.extensions;
    EXPECT_FALSE(
        CsrTemplateProcessor::Prepare(processing, unprepared, {{"hostname", "device.example"}}, {}).has_value());

    auto connection = Connection("ECDSA-P256");
    ASSERT_NE(connection, nullptr);
    CryptoContextImpl factory{connection, std::make_shared<InputTranscoder>()};
    KeyResolver keys;
    for (const auto& [name, value] : malformed)
    {
        SCOPED_TRACE(name);
        ASSERT_TRUE(value.request.Validate(processing).has_value());
        const auto calls = keys.calls;
        const auto creates = connection->creates;
        const auto generates = connection->generates;
        const auto public_key_queries = connection->public_key_queries;
        const auto closes = connection->closes;
        EXPECT_FALSE(CsrTemplateProcessor::Generate(processing, value, factory, keys).has_value());
        EXPECT_EQ(keys.calls, calls);
        EXPECT_EQ(connection->creates, creates);
        EXPECT_EQ(connection->generates, generates);
        EXPECT_EQ(connection->public_key_queries, public_key_queries);
        EXPECT_EQ(connection->closes, closes);
    }
    EXPECT_EQ(keys.calls, 0U);
    EXPECT_EQ(connection->creates, 0U);
    EXPECT_EQ(connection->generates, 0U);

    // Inclusive metadata bounds still succeed after rejected caller-built inputs.
    auto boundary = valid;
    boundary.id = std::string(kMaxTemplateIdBytes, 'i');
    boundary.submission_url.resize(kMaxSubmissionUrlBytes, 'u');
    auto output = CsrTemplateProcessor::Generate(processing, boundary, factory, keys);
    ASSERT_TRUE(output.has_value());
    EXPECT_EQ(output->id, boundary.id);
    EXPECT_EQ(output->csr->GetSubmissionUrl(), boundary.submission_url);
    EXPECT_EQ(keys.calls, 1U);
    EXPECT_EQ(connection->creates, 1U);
    EXPECT_EQ(connection->generates, 1U);
    EXPECT_EQ(connection->closes, 1U);

    std::vector<PreparedCsrTemplate> batch_values{valid};
    for (const auto& entry : malformed)
    {
        batch_values.push_back(entry.second);
    }
    batch_values.push_back(valid);
    batch_values.push_back(malformed.back().second);
    batch_values.push_back(valid);
    const auto batch = CsrTemplateProcessor::GenerateBatch(processing, batch_values, factory, keys);
    ASSERT_EQ(batch.size(), batch_values.size());
    for (std::size_t i = 0U; i < batch.size(); ++i)
    {
        SCOPED_TRACE(i);
        const bool expected = i == 0U || i == malformed.size() + 1U || i == batch.size() - 1U;
        EXPECT_EQ(batch[i].has_value(), expected);
        if (batch[i].has_value())
        {
            EXPECT_EQ(batch[i]->id, valid.id);
        }
    }
    // Only the three valid batch entries reach the resolver and provider.
    EXPECT_EQ(keys.calls, 4U);
    EXPECT_EQ(connection->creates, 4U);
    EXPECT_EQ(connection->generates, 4U);
    EXPECT_EQ(connection->closes, 4U);
}

TEST_F(CsrApiProviderTest, ExampleProfilePreservesMetadataAndEncodesOnlySubjectAndExtensions)
{
    auto value = ReferenceProfile();
    auto usage = CsrExtension::KeyUsage(processing, {CsrKeyUsage::kDigitalSignature});
    auto eku = CsrExtension::ExtendedKeyUsage(processing, {"1.3.6.1.5.5.7.3.2"});
    auto constraints = CsrExtension::BasicConstraints(processing, false);
    auto san = CsrExtension::SubjectAltNames(processing, {{CsrSanType::kDns, "device.example"}});
    ASSERT_TRUE(usage.has_value());
    ASSERT_TRUE(eku.has_value());
    ASSERT_TRUE(constraints.has_value());
    ASSERT_TRUE(san.has_value());
    value.extensions = {usage.value(), eku.value(), constraints.value(), san.value()};
    auto document = DerCsrTemplateStorage::Save(processing, value);
    ASSERT_TRUE(document.has_value());
    DerCsrTemplateStorage storage{processing, document.value()};
    EXPECT_FALSE(storage.Load("unknown-template").has_value());
    auto loaded = storage.Load(value.id);
    ASSERT_TRUE(loaded.has_value()) << "template DER bytes: " << document->size();
    EXPECT_EQ(loaded->id, value.id);
    EXPECT_EQ(loaded->key_resource, value.key_resource);
    EXPECT_EQ(loaded->algorithm, value.algorithm);
    EXPECT_EQ(loaded->submission_url, value.submission_url);
    auto prepared = CsrTemplateProcessor::Prepare(
        processing, loaded.value(), {{"DeviceId", kReferenceDeviceSerial}}, ReferenceRequirements());
    ASSERT_TRUE(prepared.has_value());
    EXPECT_EQ(prepared->id, value.id);
    EXPECT_EQ(prepared->request.subject.Attributes().back().value, kReferenceDeviceSerial);
    EXPECT_EQ(loaded->subject.Attributes().back().value, "${DeviceId}");
    auto request_der = prepared->request.ToDer(processing);
    ASSERT_TRUE(request_der.has_value());
    const std::string request_bytes(request_der->begin(), request_der->end());
    for (const auto& entry : value.issuer.Attributes())
    {
        EXPECT_EQ(request_bytes.find(entry.value), std::string::npos);
    }
    EXPECT_EQ(request_bytes.find(value.id), std::string::npos);
    EXPECT_EQ(request_bytes.find("ApplicationSigningKey"), std::string::npos);

    auto connection = Connection("ECDSA-P256");
    ASSERT_NE(connection, nullptr);
    CryptoContextImpl factory{connection, std::make_shared<InputTranscoder>()};
    KeyResolver keys{value.key_resource};
    auto output = CsrTemplateProcessor::Generate(processing, prepared.value(), factory, keys);
    ASSERT_TRUE(output.has_value());
    EXPECT_EQ(keys.calls, 1U);
    EXPECT_EQ(keys.last_resource, value.key_resource);
    EXPECT_EQ(connection->creates, 1U);
    EXPECT_EQ(connection->generates, 1U);
    EXPECT_EQ(connection->closes, 1U);
    EXPECT_EQ(output->id, value.id);
    EXPECT_EQ(output->csr->GetSubmissionUrl(), value.submission_url);
    ASSERT_EQ(output->issuer.Attributes().size(), value.issuer.Attributes().size());
    for (std::size_t i = 0; i < value.issuer.Attributes().size(); ++i)
    {
        EXPECT_EQ(output->issuer.Attributes()[i].oid, value.issuer.Attributes()[i].oid);
        EXPECT_EQ(output->issuer.Attributes()[i].value, value.issuer.Attributes()[i].value);
    }
    auto der = Der(*output->csr);
    auto req = Parse(der);
    ASSERT_NE(req, nullptr);
    EXPECT_EQ(X509_REQ_get_version(req.get()), 0L);
    EXPECT_EQ(X509_REQ_verify(req.get(), X509_REQ_get0_pubkey(req.get())), 1);
    ExpectName(X509_REQ_get_subject_name(req.get()), prepared->request.subject);
    // PKCS#10 has no issuer field. Check the entire DER as well as the exact
    // subject and attribute set so issuer metadata cannot leak into an attribute.
    const std::string encoded(der.begin(), der.end());
    for (const auto& entry : value.issuer.Attributes())
    {
        // A two-byte country code could occur by chance in the public key or
        // signature. Its absence from the DN is covered by ExpectName above.
        if (entry.value.size() > 2U)
        {
            EXPECT_EQ(encoded.find(entry.value), std::string::npos);
        }
    }
    EXPECT_EQ(encoded.find(value.id), std::string::npos);
    ASSERT_EQ(X509_REQ_get_attr_count(req.get()), 1);
    EXPECT_EQ(X509_REQ_get_attr_by_NID(req.get(), NID_ext_req, -1), 0);
    auto free_extensions = [](STACK_OF(X509_EXTENSION) * extensions) {
        sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
    };
    std::unique_ptr<STACK_OF(X509_EXTENSION), decltype(free_extensions)> extensions{X509_REQ_get_extensions(req.get()),
                                                                                    free_extensions};
    ASSERT_NE(extensions, nullptr);
    ASSERT_EQ(sk_X509_EXTENSION_num(extensions.get()), 4);
    const std::array<int, 4> nids{NID_key_usage, NID_ext_key_usage, NID_basic_constraints, NID_subject_alt_name};
    for (int i = 0; i < 4; ++i)
    {
        auto* extension = sk_X509_EXTENSION_value(extensions.get(), i);
        EXPECT_EQ(OBJ_obj2nid(X509_EXTENSION_get_object(extension)), nids[i]);
        EXPECT_EQ(X509_EXTENSION_get_critical(extension), value.extensions[i].critical ? 1 : 0);
    }
    std::unique_ptr<ASN1_BIT_STRING, decltype(&ASN1_BIT_STRING_free)> decoded_usage{
        static_cast<ASN1_BIT_STRING*>(X509V3_EXT_d2i(sk_X509_EXTENSION_value(extensions.get(), 0))),
        ASN1_BIT_STRING_free};
    ASSERT_NE(decoded_usage, nullptr);
    EXPECT_EQ(ASN1_BIT_STRING_get_bit(decoded_usage.get(), 0), 1);
    for (int bit = 1; bit < 9; ++bit)
    {
        EXPECT_EQ(ASN1_BIT_STRING_get_bit(decoded_usage.get(), bit), 0);
    }
    std::unique_ptr<EXTENDED_KEY_USAGE, decltype(&EXTENDED_KEY_USAGE_free)> decoded_eku{
        static_cast<EXTENDED_KEY_USAGE*>(X509V3_EXT_d2i(sk_X509_EXTENSION_value(extensions.get(), 1))),
        EXTENDED_KEY_USAGE_free};
    ASSERT_NE(decoded_eku, nullptr);
    ASSERT_EQ(sk_ASN1_OBJECT_num(decoded_eku.get()), 1);
    EXPECT_EQ(OBJ_obj2nid(sk_ASN1_OBJECT_value(decoded_eku.get(), 0)), NID_client_auth);
    std::unique_ptr<BASIC_CONSTRAINTS, decltype(&BASIC_CONSTRAINTS_free)> decoded_constraints{
        static_cast<BASIC_CONSTRAINTS*>(X509V3_EXT_d2i(sk_X509_EXTENSION_value(extensions.get(), 2))),
        BASIC_CONSTRAINTS_free};
    ASSERT_NE(decoded_constraints, nullptr);
    EXPECT_EQ(decoded_constraints->ca, 0);
    EXPECT_EQ(decoded_constraints->pathlen, nullptr);
    std::unique_ptr<GENERAL_NAMES, decltype(&GENERAL_NAMES_free)> decoded_names{
        static_cast<GENERAL_NAMES*>(X509V3_EXT_d2i(sk_X509_EXTENSION_value(extensions.get(), 3))), GENERAL_NAMES_free};
    ASSERT_NE(decoded_names, nullptr);
    ASSERT_EQ(sk_GENERAL_NAME_num(decoded_names.get()), 1);
    const auto* name = sk_GENERAL_NAME_value(decoded_names.get(), 0);
    ASSERT_EQ(name->type, GEN_DNS);
    EXPECT_EQ(std::string(reinterpret_cast<const char*>(ASN1_STRING_get0_data(name->d.dNSName)),
                          static_cast<std::size_t>(ASN1_STRING_length(name->d.dNSName))),
              "device.example");
}

TEST_F(CsrApiProviderTest, ExampleProfileRejectsEveryMissingRequiredAttributeAndMissingDeviceId)
{
    const auto value = ReferenceProfile();
    const auto requirements = ReferenceRequirements();
    const CsrRuntimeValues runtime{{"DeviceId", kReferenceDeviceSerial}};
    ASSERT_TRUE(CsrTemplateProcessor::Prepare(processing, value, runtime, requirements).has_value());
    for (bool issuer : {false, true})
    {
        const auto& required = issuer ? requirements.issuer_oids : requirements.subject_oids;
        for (const auto& oid : required)
        {
            SCOPED_TRACE((issuer ? "issuer " : "subject ") + oid);
            auto incomplete = value;
            auto& target = issuer ? incomplete.issuer : incomplete.subject;
            target = CsrSubject{};
            for (const auto& attribute : (issuer ? value.issuer : value.subject).Attributes())
            {
                if (attribute.oid != oid)
                {
                    ASSERT_TRUE(target.Add(processing, attribute.oid, attribute.value).has_value());
                }
            }
            EXPECT_FALSE(CsrTemplateProcessor::Prepare(processing, incomplete, runtime, requirements).has_value());
        }
    }
    EXPECT_FALSE(CsrTemplateProcessor::Prepare(processing, value, {}, requirements).has_value());
    EXPECT_FALSE(CsrTemplateProcessor::Prepare(processing, value, {{"DeviceId", ""}}, requirements).has_value());
    EXPECT_FALSE(
        CsrTemplateProcessor::Prepare(processing, value, {{"serial", "wrong-variable"}}, requirements).has_value());
}

TEST_F(CsrApiProviderTest, TestLevelCaIssuesCertificateWhosePublicKeyMatchesReferenceCsr)
{
    // OpenSSL-only issuance check, not certificate-slot installation integration.
    const auto value = ReferenceProfile();
    auto prepared = CsrTemplateProcessor::Prepare(
        processing, value, {{"DeviceId", kReferenceDeviceSerial}}, ReferenceRequirements());
    ASSERT_TRUE(prepared.has_value());
    auto connection = Connection("ECDSA-P256");
    ASSERT_NE(connection, nullptr);
    CryptoContextImpl factory{connection, std::make_shared<InputTranscoder>()};
    KeyResolver keys{value.key_resource};
    auto output = CsrTemplateProcessor::Generate(processing, prepared.value(), factory, keys);
    ASSERT_TRUE(output.has_value());
    auto req = Parse(Der(*output->csr));
    ASSERT_NE(req, nullptr);
    ASSERT_EQ(X509_REQ_verify(req.get(), X509_REQ_get0_pubkey(req.get())), 1);

    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> ca_key{EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "prime256v1"),
                                                               EVP_PKEY_free};
    ASSERT_NE(ca_key, nullptr);
    std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)> issuer{X509_NAME_new(), X509_NAME_free};
    ASSERT_NE(issuer, nullptr);
    for (const auto& attribute : prepared->issuer.Attributes())
    {
        ASSERT_EQ(X509_NAME_add_entry_by_txt(issuer.get(),
                                             attribute.oid.c_str(),
                                             MBSTRING_UTF8,
                                             reinterpret_cast<const unsigned char*>(attribute.value.data()),
                                             static_cast<int>(attribute.value.size()),
                                             -1,
                                             0),
                  1);
    }
    std::unique_ptr<X509, decltype(&X509_free)> certificate{X509_new(), X509_free};
    ASSERT_NE(certificate, nullptr);
    ASSERT_EQ(X509_set_version(certificate.get(), 2L), 1);
    ASSERT_EQ(ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 1L), 1);
    ASSERT_NE(X509_gmtime_adj(X509_getm_notBefore(certificate.get()), 0L), nullptr);
    ASSERT_NE(X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 3600L), nullptr);
    ASSERT_EQ(X509_set_subject_name(certificate.get(), X509_REQ_get_subject_name(req.get())), 1);
    ASSERT_EQ(X509_set_issuer_name(certificate.get(), issuer.get()), 1);
    ASSERT_EQ(X509_set_pubkey(certificate.get(), X509_REQ_get0_pubkey(req.get())), 1);
    ASSERT_GT(X509_sign(certificate.get(), ca_key.get(), EVP_sha256()), 0);
    // Reparse issued DER to check the actual certificate, not just builder state.
    const int size = i2d_X509(certificate.get(), nullptr);
    ASSERT_GT(size, 0);
    std::vector<uint8_t> der(static_cast<std::size_t>(size));
    auto* write = der.data();
    ASSERT_EQ(i2d_X509(certificate.get(), &write), size);
    const auto* read = der.data();
    std::unique_ptr<X509, decltype(&X509_free)> issued{d2i_X509(nullptr, &read, size), X509_free};
    ASSERT_NE(issued, nullptr);
    EXPECT_EQ(read, der.data() + der.size());
    EXPECT_EQ(X509_verify(issued.get(), ca_key.get()), 1);
    EXPECT_EQ(EVP_PKEY_eq(X509_get0_pubkey(issued.get()), X509_REQ_get0_pubkey(req.get())), 1);
    EXPECT_EQ(EVP_PKEY_eq(X509_get0_pubkey(issued.get()), ca_key.get()), 0);
    ExpectName(X509_get_subject_name(issued.get()), prepared->request.subject);
    ExpectName(X509_get_issuer_name(issued.get()), prepared->issuer);
}
}  // namespace
}  // namespace score::crypto

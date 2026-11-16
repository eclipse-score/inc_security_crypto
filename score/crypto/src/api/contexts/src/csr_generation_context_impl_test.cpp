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

#include "score/crypto/src/api/contexts/src/csr_generation_context_impl.hpp"
#include "score/crypto/src/api/src/crypto_context_impl.hpp"
#include "score/crypto/src/common/csr_der.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/common/context_mode.hpp"
#include "score/crypto/src/daemon/common/context_types.hpp"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/csr_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/csr/csr_processing.hpp"
#include <gtest/gtest.h>
#include <openssl/x509v3.h>
#include <algorithm>
#include <array>
#include <limits>
#include <memory>
#include <optional>

namespace score::crypto
{
namespace
{
namespace proto = daemon::control_plane::protocol;
namespace csr = daemon::provider::handler::csr_handler_operations;
const proto::OperationIdentifier kGenerate{daemon::common::actors::OP_ACTOR_CSR_HANDLER, csr::CSR_GENERATE_NATIVE};
const proto::OperationIdentifier kPublicKeyInfo{daemon::common::actors::OP_ACTOR_CSR_HANDLER, csr::CSR_PUBLIC_KEY_INFO};
using RequestPtr = std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)>;
NativeCsrProcessing processing;
struct ExtensionsDeleter
{
    void operator()(STACK_OF(X509_EXTENSION) * extensions) const
    {
        sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
    }
};
using ExtensionsPtr = std::unique_ptr<STACK_OF(X509_EXTENSION), ExtensionsDeleter>;

std::string Asn1Text(const ASN1_STRING* value)
{
    if (value == nullptr || ASN1_STRING_length(value) <= 0)
    {
        return {};
    }
    return {reinterpret_cast<const char*>(ASN1_STRING_get0_data(value)),
            static_cast<std::size_t>(ASN1_STRING_length(value))};
}

std::string SubjectValue(X509_REQ* request, int nid)
{
    auto* name = X509_REQ_get_subject_name(request);
    const int index = X509_NAME_get_index_by_NID(name, nid, -1);
    if (index < 0)
    {
        return {};
    }
    return Asn1Text(X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name, index)));
}

std::string ChallengePassword(X509_REQ* request)
{
    const int index = X509_REQ_get_attr_by_NID(request, NID_pkcs9_challengePassword, -1);
    if (index < 0)
    {
        return {};
    }
    auto* value = X509_ATTRIBUTE_get0_type(X509_REQ_get_attr(request, index), 0);
    if (value == nullptr)
    {
        return {};
    }
    const int type = ASN1_TYPE_get(value);
    if (type != V_ASN1_UTF8STRING && type != V_ASN1_PRINTABLESTRING && type != V_ASN1_T61STRING)
    {
        return {};
    }
    return Asn1Text(value->value.asn1_string);
}

std::vector<uint8_t> PublicKeyInfo(uint8_t first_byte = 1U)
{
    // Construct a public-only fixture, using the same public codec APIs as the
    // shared request tests. No signing key or private-key encoding is needed.
    std::array<unsigned char, 32> raw_key{};
    raw_key[0] = first_byte;
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key{
        EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, raw_key.data(), raw_key.size()), EVP_PKEY_free};
    if (!key)
    {
        return {};
    }
    const int length = i2d_PUBKEY(key.get(), nullptr);
    if (length <= 0)
    {
        return {};
    }
    std::vector<uint8_t> der(static_cast<std::size_t>(length));
    auto* cursor = der.data();
    if (i2d_PUBKEY(key.get(), &cursor) != length || cursor != der.data() + der.size())
    {
        return {};
    }
    return der;
}

class TestTranscoder final : public IBufferTranscoder
{
  public:
    Expected<TranscoderSpan, score::result::Error> AcquireInputShm(score::cpp::span<const uint8_t> data) override
    {
        ++input_shm_acquisitions;
        return Acquire(data, false);
    }
    Expected<TranscoderSpan, score::result::Error> Acquire(score::cpp::span<const uint8_t> data,
                                                           bool output = false) override
    {
        ++acquisitions;
        if (fail || (output && fail_output))
        {
            return make_unexpected(MakeError(CryptoErrorCode::kAllocationFailed, "test"));
        }
        TranscoderSpan token;
        if (output)
        {
            ++output_acquisitions;
            buffer = {const_cast<uint8_t*>(data.data()), data.size()};
            token.set_kind(inline_output ? TranscoderSpan::Kind::kInBand : TranscoderSpan::Kind::kBulk);
            token.set_caller_span(buffer);
        }
        else
        {
            input.assign(data.begin(), data.end());
            if (shm)
            {
                token.set_kind(TranscoderSpan::Kind::kBulk);
                token.obj_node_offset() = {99U, 0U};
                token.set_caller_span({const_cast<uint8_t*>(data.data()), data.size()});
            }
        }
        return token;
    }
    void AppendInputBuffer(proto::OperationRequestBuilder& builder, TranscoderSpan& token) override
    {
        EXPECT_EQ(token.kind(), shm ? TranscoderSpan::Kind::kBulk : TranscoderSpan::Kind::kInBand);
        if (shm)
        {
            builder.with_shm(99U, 0U, input.size(), daemon::common::ShmDirection::In);
        }
        else
        {
            builder.with_in_data_buffer(input);
        }
    }
    void AppendOutputBuffer(proto::OperationRequestBuilder& builder, TranscoderSpan& token) override
    {
        if (inline_output)
        {
            EXPECT_EQ(token.kind(), TranscoderSpan::Kind::kInBand);
            return;
        }
        EXPECT_EQ(token.kind(), TranscoderSpan::Kind::kBulk);
        builder.with_shm(99U, csr::kMaxInputDerBytes, token.caller_span().size(), daemon::common::ShmDirection::InOut);
    }
    score::Result<std::size_t> ExtractOutputBuffer(TranscoderSpan& token,
                                                   proto::ControlResponseValidator& validator,
                                                   std::size_t param_idx) override
    {
        if (processing_response)
        {
            processing_response = false;
        }
        else
        {
            ++extractions;
        }
        if (fail_extract)
        {
            return score::Unexpected{MakeError(CryptoErrorCode::kInternalError, "test extraction failure")};
        }
        if (token.kind() == TranscoderSpan::Kind::kInBand)
        {
            auto data = validator.getParameterAt<daemon::common::OwnedBuffer>(0U, param_idx);
            if (!data.has_value())
            {
                return score::Unexpected{MakeError(CryptoErrorCode::kOperationFailed, "invalid inline output")};
            }
            if (data->size() > token.caller_span().size())
            {
                return score::Unexpected{
                    MakeError(CryptoErrorCode::kInsufficientBufferSize, "inline output too large")};
            }
            std::copy(data->begin(), data->end(), token.caller_span().begin());
            return extracted_count.value_or(data->size());
        }
        auto written = validator.getParameterAt<uint64_t>(0U, param_idx);
        if (!written.has_value())
        {
            return score::Unexpected{MakeError(CryptoErrorCode::kOperationFailed, "invalid byte count")};
        }
        if (written.value() > token.caller_span().size())
        {
            return score::Unexpected{MakeError(CryptoErrorCode::kInsufficientBufferSize, "invalid byte count")};
        }
        return extracted_count.value_or(static_cast<std::size_t>(written.value()));
    }
    std::vector<uint8_t> input;
    score::cpp::span<uint8_t> buffer{};
    bool fail{false};
    bool fail_output{false};
    bool fail_extract{false};
    bool shm{false};
    bool inline_output{false};
    bool processing_response{false};
    std::optional<std::size_t> extracted_count;
    unsigned acquisitions{0U};
    unsigned input_shm_acquisitions{0U};
    unsigned output_acquisitions{0U};
    unsigned extractions{0U};
};

class TestConnection final : public api::control_plane::IConnection
{
  public:
    explicit TestConnection(std::shared_ptr<TestTranscoder> transcoder) : transcoder_{std::move(transcoder)} {}
    Expected<proto::ControlResponse, CryptoErrorCode> SendRequest(const proto::ControlRequest& request) override
    {
        EXPECT_EQ(request.operation.operations.size(), 1U);
        const auto& operation = request.operation.operations.front();
        proto::ControlResponse response;
        proto::SingleOperationResponse result{operation.operationId, proto::OPERATION_RESULT_SUCCESS, {}};
        if (SameOperation(operation.operationId, daemon::mediator::operations::CloseContext()))
        {
            ++closes;
            EXPECT_EQ(request.data_node_id, 42U);
        }
        else if (SameOperation(operation.operationId, daemon::mediator::operations::CreateContext()))
        {
            ++creates;
            EXPECT_EQ(request.data_node_id, 1U);
            ASSERT_CREATE(operation);
            result.parameters.emplace_back(context_id);
        }
        else if (SameOperation(operation.operationId, daemon::mediator::operations::ProcessCsr()))
        {
            // Explicit test-only daemon bridge. Keep generation metrics
            // separate from helper RPCs without replacing the production client.
            ++processing_calls;
            EXPECT_EQ(request.data_node_id, 1U);
            if (transport_error)
            {
                return make_unexpected(*transport_error);
            }
            auto document = score::crypto::csr::wire::Decode(transcoder_->input);
            if (!document.has_value())
            {
                return make_unexpected(CryptoErrorCode::kInvalidArgument);
            }
            auto processed = processing.Process(document.value());
            transcoder_->acquisitions -= 2U;
            --transcoder_->input_shm_acquisitions;
            --transcoder_->output_acquisitions;
            if (!processed.has_value())
            {
                result.result = static_cast<proto::OperationResult>(*processed.error());
            }
            else
            {
                if (processing_extra_field)
                {
                    processed->text = "unexpected";
                }
                if (processing_wrong_action)
                {
                    processed->action = score::crypto::csr::wire::Action::Validate;
                }
                auto encoded = score::crypto::csr::wire::Encode(processed.value());
                if (!encoded.has_value())
                {
                    return make_unexpected(CryptoErrorCode::kInvalidArgument);
                }
                if (processing_trailing_data)
                {
                    encoded->push_back(0U);
                }
                if (transcoder_->inline_output)
                {
                    result.parameters.emplace_back(std::move(encoded.value()));
                }
                else
                {
                    std::copy(encoded->begin(), encoded->end(), transcoder_->buffer.begin());
                    result.parameters.emplace_back(written_count.value_or(static_cast<uint64_t>(encoded->size())));
                }
                transcoder_->processing_response = true;
            }
            if (daemon_error != static_cast<CryptoErrorCode>(0U))
            {
                result.result = static_cast<proto::OperationResult>(daemon_error);
            }
            if (wrong_type)
            {
                result.parameters = {uint8_t{1U}};
            }
            if (extra_parameter)
            {
                result.parameters.emplace_back(uint64_t{1U});
            }
            if (missing_parameter)
            {
                result.parameters.clear();
            }
            if (wrong_actor)
            {
                result.operationId.operationActor = 0U;
            }
            if (wrong_action)
            {
                result.operationId.operationAction = 0U;
            }
        }
        else
        {
            const bool public_info = SameOperation(operation.operationId, kPublicKeyInfo);
            if (public_info)
            {
                ++public_info_queries;
            }
            else
            {
                ++generates;
                EXPECT_TRUE(SameOperation(operation.operationId, kGenerate));
            }
            EXPECT_EQ(request.data_node_id, 42U);
            const std::size_t input_count = public_info ? 0U : 1U;
            EXPECT_EQ(operation.parameters.size(), input_count + (transcoder_->inline_output ? 0U : 1U));
            if (!transcoder_->inline_output && operation.parameters.size() > input_count)
            {
                const auto* output = std::get_if<daemon::common::DataShm>(&operation.parameters[input_count]);
                EXPECT_NE(output, nullptr);
                if (output != nullptr)
                {
                    EXPECT_EQ(output->node_id, 99U);
                    EXPECT_EQ(output->offset, csr::kMaxInputDerBytes);
                    EXPECT_EQ(output->size, csr::kMaxDerBytes);
                    EXPECT_EQ(output->direction, daemon::common::ShmDirection::InOut);
                }
            }
            if (!public_info && !operation.parameters.empty())
            {
                EXPECT_EQ(std::holds_alternative<daemon::common::DataShm>(operation.parameters[0]), transcoder_->shm);
                if (transcoder_->shm)
                {
                    const auto& input = std::get<daemon::common::DataShm>(operation.parameters[0]);
                    EXPECT_EQ(input.node_id, 99U);
                    EXPECT_EQ(input.offset, 0U);
                    EXPECT_EQ(input.size, transcoder_->input.size());
                    EXPECT_EQ(input.direction, daemon::common::ShmDirection::In);
                }
            }
            if (transport_error)
            {
                return make_unexpected(*transport_error);
            }
            if (!public_info)
            {
                auto document = score::crypto::csr::wire::Decode(transcoder_->input);
                if (!document.has_value())
                {
                    return make_unexpected(CryptoErrorCode::kInvalidArgument);
                }
                auto input = NativeCsrProcessing::GenerationRequest(document.value());
                if (!input.has_value())
                {
                    result.result = static_cast<proto::OperationResult>(*input.error());
                }
                else
                {
                    auto encoded = NativeCsrProcessing::ToDer(input.value(), public_key_info);
                    if (!encoded.has_value())
                    {
                        result.result = static_cast<proto::OperationResult>(*encoded.error());
                    }
                }
            }
            if (daemon_error != static_cast<CryptoErrorCode>(0U))
            {
                result.result = static_cast<proto::OperationResult>(daemon_error);
            }
            const auto& data = public_info ? public_key_info : der;
            if (transcoder_->inline_output)
            {
                if (wrong_type)
                {
                    result.parameters.emplace_back(uint64_t{data.size()});
                }
                else
                {
                    result.parameters.emplace_back(daemon::common::OwnedBuffer{data});
                }
            }
            else if (wrong_type)
            {
                result.parameters.emplace_back(daemon::common::OwnedBuffer{data});
            }
            else
            {
                if (data.size() <= transcoder_->buffer.size())
                {
                    std::copy(data.begin(), data.end(), transcoder_->buffer.begin());
                }
                result.parameters.emplace_back(written_count.value_or(static_cast<uint64_t>(data.size())));
            }
            if (extra_parameter)
            {
                result.parameters.emplace_back(uint64_t{1U});
            }
            if (missing_parameter)
            {
                result.parameters.clear();
            }
            if (wrong_actor)
            {
                result.operationId.operationActor = 0U;
            }
            if (wrong_action)
            {
                result.operationId.operationAction = 0U;
            }
        }
        response.operation.operations.push_back(std::move(result));
        if (extra_operation)
        {
            response.operation.operations.push_back({kGenerate, 0U, {}});
        }
        if (missing_operation)
        {
            response.operation.operations.clear();
        }
        return response;
    }
    void ASSERT_CREATE(const proto::SingleOperationRequest& operation)
    {
        ASSERT_EQ(operation.parameters.size(), 7U);
        EXPECT_EQ(std::get<std::string_view>(operation.parameters[0]), daemon::common::context_types::kCsrGeneration);
        EXPECT_EQ(std::get<std::string_view>(operation.parameters[1]), "ECDSA-P256-SHA256");
        EXPECT_EQ(std::get<uint64_t>(operation.parameters[3]), 17U);
        EXPECT_EQ(std::get<uint8_t>(operation.parameters[4]),
                  static_cast<uint8_t>(daemon::common::ContextMode::kGenerate));
        EXPECT_TRUE(std::holds_alternative<daemon::common::NoParam>(operation.parameters[5]));
        EXPECT_TRUE(std::holds_alternative<daemon::common::NoParam>(operation.parameters[6]));
    }
    static bool SameOperation(const proto::OperationIdentifier& left, const proto::OperationIdentifier& right)
    {
        return left.operationActor == right.operationActor && left.operationAction == right.operationAction;
    }
    proto::DataNodeId GetConnectionNodeId() const override
    {
        return 1U;
    }
    unsigned creates{0U};
    unsigned closes{0U};
    unsigned generates{0U};
    unsigned public_info_queries{0U};
    unsigned processing_calls{0U};
    uint64_t context_id{42U};
    CryptoErrorCode daemon_error{static_cast<CryptoErrorCode>(0U)};
    std::optional<CryptoErrorCode> transport_error;
    std::optional<uint64_t> written_count;
    bool wrong_type{false};
    bool wrong_actor{false};
    bool wrong_action{false};
    bool extra_parameter{false};
    bool extra_operation{false};
    bool missing_parameter{false};
    bool missing_operation{false};
    bool processing_extra_field{false};
    bool processing_wrong_action{false};
    bool processing_trailing_data{false};
    std::vector<uint8_t> der{0x30, 0x02, 0x05, 0x00};
    std::vector<uint8_t> public_key_info = PublicKeyInfo();  // Daemon-side bound-public-key fixture only.
  private:
    std::shared_ptr<TestTranscoder> transcoder_;
};

class CsrContextTest : public ::testing::Test
{
  protected:
    CsrGenerationContextConfig Config()
    {
        CryptoResourceId key;
        key.id = 17U;
        key.type = ResourceType::kKey;
        CsrGenerationContextConfig config;
        config.SetKey(key).SetAlgorithm("ECDSA-P256-SHA256").SetSubmissionUrl("https://ca.example/enroll");
        return config;
    }
    RequestPtr DecodeInput()
    {
        RequestPtr decoded{X509_REQ_new(), X509_REQ_free};
        EXPECT_TRUE(decoded);
        if (decoded)
        {
            auto document = score::crypto::csr::wire::Decode(transcoder->input);
            if (!document.has_value())
            {
                decoded.reset();
                return decoded;
            }
            auto input = NativeCsrProcessing::GenerationRequest(document.value());
            if (!input.has_value())
            {
                decoded.reset();
                return decoded;
            }
            auto der = NativeCsrProcessing::ToDer(input.value(), connection->public_key_info);
            if (!der.has_value())
            {
                decoded.reset();
                return decoded;
            }
            auto populated = score::crypto::csr::der::PopulateRequest(decoded.get(), der.value());
            EXPECT_TRUE(populated.has_value());
            if (!populated.has_value())
            {
                decoded.reset();
            }
        }
        return decoded;
    }
    std::shared_ptr<TestTranscoder> transcoder = std::make_shared<TestTranscoder>();
    std::shared_ptr<TestConnection> connection = std::make_shared<TestConnection>(transcoder);
    CryptoContextImpl factory{connection, transcoder};
};

TEST_F(CsrContextTest, PublicFactoryBindsKeyAndExportsOwnedDerAfterContextDestruction)
{
    ICsrExport::Uptr exported;
    {
        auto created = factory.CreateCsrGenerationContext(Config());
        ASSERT_TRUE(created.has_value());
        auto& context = *created.value();
        EXPECT_TRUE(context.SetSubjectKey(Config().key).has_value());
        EXPECT_TRUE(context.SetSignatureAlgorithm(Config().algorithm).has_value());
        ASSERT_TRUE(context.SetSubjectDn("CN=device,O=organization,C=DE").has_value());
        ASSERT_TRUE(context.AddSubjectAltName("DNS:device.example").has_value());
        ASSERT_TRUE(context.AddSubjectAltName("IP:127.0.0.1").has_value());
        ASSERT_TRUE(context.SetChallengePassword("password").has_value());
        auto result = context.Generate();
        ASSERT_TRUE(result.has_value());
        exported = std::move(result.value());
        EXPECT_EQ(connection->creates, 1U);
        EXPECT_EQ(connection->generates, 1U);
        auto decoded = DecodeInput();
        ASSERT_TRUE(decoded);
        EXPECT_EQ(SubjectValue(decoded.get(), NID_commonName), "device");
        EXPECT_EQ(SubjectValue(decoded.get(), NID_organizationName), "organization");
        EXPECT_EQ(SubjectValue(decoded.get(), NID_countryName), "DE");
        EXPECT_EQ(ChallengePassword(decoded.get()), "password");
        EXPECT_EQ(X509_REQ_get0_pubkey(decoded.get()), nullptr);
        ExtensionsPtr extensions{X509_REQ_get_extensions(decoded.get())};
        ASSERT_TRUE(extensions);
        ASSERT_EQ(sk_X509_EXTENSION_num(extensions.get()), 1);
        auto* extension = sk_X509_EXTENSION_value(extensions.get(), 0);
        EXPECT_EQ(OBJ_obj2nid(X509_EXTENSION_get_object(extension)), NID_subject_alt_name);
        std::unique_ptr<GENERAL_NAMES, decltype(&GENERAL_NAMES_free)> names{
            static_cast<GENERAL_NAMES*>(X509V3_EXT_d2i(extension)), GENERAL_NAMES_free};
        ASSERT_TRUE(names);
        ASSERT_EQ(sk_GENERAL_NAME_num(names.get()), 2);
        auto* dns = sk_GENERAL_NAME_value(names.get(), 0);
        ASSERT_EQ(dns->type, GEN_DNS);
        EXPECT_EQ(Asn1Text(dns->d.dNSName), "device.example");
        auto* ip = sk_GENERAL_NAME_value(names.get(), 1);
        ASSERT_EQ(ip->type, GEN_IPADD);
        ASSERT_EQ(ASN1_STRING_length(ip->d.iPAddress), 4);
        const std::array<uint8_t, 4> expected_ip{127U, 0U, 0U, 1U};
        EXPECT_TRUE(std::equal(expected_ip.begin(), expected_ip.end(), ASN1_STRING_get0_data(ip->d.iPAddress)));
        EXPECT_TRUE(context.Generate().has_value());
        EXPECT_EQ(connection->public_info_queries, 0U);
        EXPECT_EQ(transcoder->input_shm_acquisitions, 2U);
    }
    EXPECT_EQ(connection->closes, 1U);
    ASSERT_NE(exported, nullptr);
    EXPECT_EQ(exported->GetSubmissionUrl(), "https://ca.example/enroll");
    EXPECT_EQ(exported->GetEncodedCsrLength(), connection->der.size());
    std::array<uint8_t, 3> short_buffer{0xAA, 0xAA, 0xAA};
    EXPECT_FALSE(exported->GetEncodedCsr(short_buffer).has_value());
    EXPECT_EQ(short_buffer, (std::array<uint8_t, 3>{0xAA, 0xAA, 0xAA}));
    std::vector<uint8_t> buffer(exported->GetEncodedCsrLength());
    auto written = exported->GetEncodedCsr(buffer);
    ASSERT_TRUE(written.has_value());
    EXPECT_EQ(written.value(), buffer.size());
    EXPECT_EQ(buffer, connection->der);
}

TEST_F(CsrContextTest, SettersAreTransactionalAndCannotRebindTheDaemonKey)
{
    auto context = factory.CreateCsrGenerationContext(Config());
    ASSERT_TRUE(context.has_value());
    EXPECT_FALSE(context.value()->Generate().has_value());
    EXPECT_EQ(transcoder->acquisitions, 0U);
    ASSERT_TRUE(context.value()->SetSubjectDn("CN=original").has_value());
    EXPECT_FALSE(context.value()->SetSubjectDn("CN=broken,").has_value());
    EXPECT_FALSE(context.value()->SetSubject(CsrSubject{}).has_value());
    ASSERT_TRUE(context.value()->SetChallengePassword("original-password").has_value());
    EXPECT_FALSE(context.value()->SetChallengePassword(std::string(256U, 'x')).has_value());
    auto key = Config().key;
    ++key.id;
    EXPECT_FALSE(context.value()->SetSubjectKey(key).has_value());
    EXPECT_FALSE(context.value()->SetSignatureAlgorithm("Ed25519").has_value());
    auto usage = CsrExtension::KeyUsage(processing, {CsrKeyUsage::kDigitalSignature});
    ASSERT_TRUE(usage.has_value());
    ASSERT_TRUE(context.value()->AddExtension(usage.value()).has_value());
    EXPECT_FALSE(context.value()->AddExtension(usage.value()).has_value());
    ASSERT_TRUE(context.value()->AddSubjectAltName("DNS:original.example").has_value());
    EXPECT_FALSE(context.value()->AddSubjectAltName("DNS:host,IP:injected").has_value());
    EXPECT_EQ(transcoder->acquisitions, 0U);
    EXPECT_TRUE(context.value()->Generate().has_value());
    auto decoded = DecodeInput();
    ASSERT_TRUE(decoded);
    EXPECT_EQ(SubjectValue(decoded.get(), NID_commonName), "original");
    EXPECT_EQ(ChallengePassword(decoded.get()), "original-password");
    ExtensionsPtr extensions{X509_REQ_get_extensions(decoded.get())};
    ASSERT_TRUE(extensions);
    ASSERT_EQ(sk_X509_EXTENSION_num(extensions.get()), 2);
    auto* usage_extension = sk_X509_EXTENSION_value(extensions.get(), 0);
    EXPECT_EQ(OBJ_obj2nid(X509_EXTENSION_get_object(usage_extension)), NID_key_usage);
    EXPECT_EQ(X509_EXTENSION_get_critical(usage_extension), 1);
    std::unique_ptr<ASN1_BIT_STRING, decltype(&ASN1_BIT_STRING_free)> bits{
        static_cast<ASN1_BIT_STRING*>(X509V3_EXT_d2i(usage_extension)), ASN1_BIT_STRING_free};
    ASSERT_TRUE(bits);
    EXPECT_EQ(ASN1_BIT_STRING_get_bit(bits.get(), 0), 1);
    auto* san_extension = sk_X509_EXTENSION_value(extensions.get(), 1);
    EXPECT_EQ(OBJ_obj2nid(X509_EXTENSION_get_object(san_extension)), NID_subject_alt_name);
    std::unique_ptr<GENERAL_NAMES, decltype(&GENERAL_NAMES_free)> names{
        static_cast<GENERAL_NAMES*>(X509V3_EXT_d2i(san_extension)), GENERAL_NAMES_free};
    ASSERT_TRUE(names);
    ASSERT_EQ(sk_GENERAL_NAME_num(names.get()), 1);
    auto* dns = sk_GENERAL_NAME_value(names.get(), 0);
    ASSERT_EQ(dns->type, GEN_DNS);
    EXPECT_EQ(Asn1Text(dns->d.dNSName), "original.example");
    EXPECT_EQ(connection->public_info_queries, 0U);
}

TEST_F(CsrContextTest, RejectsInvalidAndUnsupportedConfigurationWithoutIpc)
{
    auto config = Config();
    config.key.id = 0U;
    EXPECT_FALSE(factory.CreateCsrGenerationContext(config).has_value());
    config = Config();
    config.key.type = ResourceType::kProvider;
    EXPECT_FALSE(factory.CreateCsrGenerationContext(config).has_value());
    config = Config();
    config.algorithm = "";
    EXPECT_FALSE(factory.CreateCsrGenerationContext(config).has_value());
    config = Config();
    config.algorithm = std::string(65U, 'x');
    EXPECT_FALSE(factory.CreateCsrGenerationContext(config).has_value());
    config = Config();
    config.provider = CryptoResourceId{};
    EXPECT_FALSE(factory.CreateCsrGenerationContext(config).has_value());
    config = Config();
    config.SetExtendedParameter("unknown", "x");
    EXPECT_FALSE(factory.CreateCsrGenerationContext(config).has_value());
    config = Config();
    config.DisableTimeout();
    EXPECT_FALSE(factory.CreateCsrGenerationContext(config).has_value());
    config = Config();
    config.SetOperationTimeout(std::chrono::milliseconds{10});
    EXPECT_FALSE(factory.CreateCsrGenerationContext(config).has_value());
    EXPECT_EQ(connection->creates, 0U);
}

TEST_F(CsrContextTest, BothBuffersUseSharedMemoryAndAcquisitionErrorsArePreserved)
{
    auto created = factory.CreateCsrGenerationContext(Config());
    ASSERT_TRUE(created.has_value());
    ASSERT_TRUE(created.value()->SetSubjectDn("CN=device").has_value());
    transcoder->fail = true;
    auto failed = created.value()->Generate();
    ASSERT_FALSE(failed.has_value());
    EXPECT_EQ(*failed.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kAllocationFailed));
    EXPECT_EQ(connection->generates, 0U);
    transcoder->fail = false;
    transcoder->fail_output = true;
    failed = created.value()->Generate();
    ASSERT_FALSE(failed.has_value());
    EXPECT_EQ(*failed.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kAllocationFailed));
    EXPECT_EQ(connection->generates, 0U);
    transcoder->fail_output = false;
    transcoder->shm = true;
    EXPECT_TRUE(created.value()->Generate().has_value());
    EXPECT_EQ(transcoder->output_acquisitions, 1U);
    EXPECT_EQ(transcoder->extractions, 1U);
}

TEST_F(CsrContextTest, MinimalSubjectStillAcquiresInputSharedMemory)
{
    auto created = factory.CreateCsrGenerationContext(Config());
    ASSERT_TRUE(created.has_value());
    ASSERT_TRUE(created.value()->SetSubjectDn("CN=x").has_value());
    transcoder->shm = true;
    ASSERT_TRUE(created.value()->Generate().has_value());
    EXPECT_LE(transcoder->input.size(), score::crypto::csr::wire::kMaxWireBytes);
    EXPECT_EQ(transcoder->input_shm_acquisitions, 1U);
    EXPECT_EQ(transcoder->output_acquisitions, 1U);
    EXPECT_EQ(connection->public_info_queries, 0U);
    auto decoded = DecodeInput();
    ASSERT_TRUE(decoded);
    EXPECT_EQ(SubjectValue(decoded.get(), NID_commonName), "x");
}

TEST_F(CsrContextTest, TypedExtensionsEncodeWithoutPublicKeyQuery)
{
    auto created = factory.CreateCsrGenerationContext(Config());
    ASSERT_TRUE(created.has_value());
    ASSERT_TRUE(created.value()->SetSubjectDn("CN=device").has_value());
    auto usage = CsrExtension::KeyUsage(processing, {CsrKeyUsage::kDigitalSignature});
    auto extended_usage = CsrExtension::ExtendedKeyUsage(processing, {"1.3.6.1.5.5.7.3.2"});
    auto constraints = CsrExtension::BasicConstraints(processing, false);
    const std::array<uint8_t, 2> value{0x05U, 0U};
    auto custom = CsrExtension::CustomDer(processing, "1.2.3.4", value);
    ASSERT_TRUE(usage.has_value());
    ASSERT_TRUE(extended_usage.has_value());
    ASSERT_TRUE(constraints.has_value());
    ASSERT_TRUE(custom.has_value());
    for (const auto& extension : {usage.value(), extended_usage.value(), constraints.value(), custom.value()})
    {
        ASSERT_TRUE(created.value()->AddExtension(extension).has_value());
    }
    ASSERT_TRUE(created.value()->AddSubjectAltName("DNS:device.example").has_value());
    ASSERT_TRUE(created.value()->Generate().has_value());
    EXPECT_EQ(connection->public_info_queries, 0U);
    auto decoded = DecodeInput();
    ASSERT_TRUE(decoded);
    ExtensionsPtr extensions{X509_REQ_get_extensions(decoded.get())};
    ASSERT_TRUE(extensions);
    EXPECT_EQ(sk_X509_EXTENSION_num(extensions.get()), 5);
    EXPECT_EQ(X509_REQ_get0_pubkey(decoded.get()), nullptr);
}

TEST_F(CsrContextTest, KeyDependentExtensionUsesDaemonContextWithoutClientSpki)
{
    auto created = factory.CreateCsrGenerationContext(Config());
    ASSERT_TRUE(created.has_value());
    // Structural setters accept a key-dependent config without encoding it or
    // committing the validation-only subject used before SetSubject.
    ASSERT_TRUE(created.value()->AddExtension({"2.5.29.14", false, "hash"}).has_value());
    ASSERT_TRUE(created.value()->SetChallengePassword("password").has_value());
    auto failed = created.value()->Generate();
    ASSERT_FALSE(failed.has_value());
    EXPECT_EQ(*failed.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kInvalidArgument));
    EXPECT_EQ(transcoder->acquisitions, 0U);
    EXPECT_EQ(connection->public_info_queries, 0U);
    ASSERT_TRUE(created.value()->SetSubjectDn("CN=device").has_value());
    connection->public_key_info = PublicKeyInfo();
    ASSERT_FALSE(connection->public_key_info.empty());
    transcoder->shm = true;
    ASSERT_TRUE(created.value()->Generate().has_value());
    EXPECT_EQ(connection->public_info_queries, 0U);
    EXPECT_EQ(connection->generates, 1U);
    EXPECT_EQ(transcoder->input_shm_acquisitions, 1U);
    EXPECT_EQ(transcoder->output_acquisitions, 1U);
    EXPECT_EQ(transcoder->extractions, 1U);
    auto decoded = DecodeInput();
    ASSERT_TRUE(decoded);
    EXPECT_EQ(SubjectValue(decoded.get(), NID_commonName), "device");
    EXPECT_EQ(ChallengePassword(decoded.get()), "password");
    EXPECT_EQ(X509_REQ_get0_pubkey(decoded.get()), nullptr);
    ExtensionsPtr extensions{X509_REQ_get_extensions(decoded.get())};
    ASSERT_TRUE(extensions);
    ASSERT_EQ(sk_X509_EXTENSION_num(extensions.get()), 1);
    auto* extension = sk_X509_EXTENSION_value(extensions.get(), 0);
    EXPECT_EQ(OBJ_obj2nid(X509_EXTENSION_get_object(extension)), NID_subject_key_identifier);
    std::unique_ptr<ASN1_OCTET_STRING, decltype(&ASN1_OCTET_STRING_free)> identifier{
        static_cast<ASN1_OCTET_STRING*>(X509V3_EXT_d2i(extension)), ASN1_OCTET_STRING_free};
    ASSERT_TRUE(identifier);
    EXPECT_EQ(ASN1_STRING_length(identifier.get()), 20);
    const auto first_input = transcoder->input;
    connection->public_key_info = PublicKeyInfo(2U);
    ASSERT_FALSE(connection->public_key_info.empty());
    ASSERT_TRUE(created.value()->Generate().has_value());
    EXPECT_EQ(connection->public_info_queries, 0U);
    EXPECT_EQ(connection->generates, 2U);
    EXPECT_EQ(transcoder->input, first_input);  // No bound public key travels in native wire input.
}

TEST_F(CsrContextTest, NativeGenerationAllocationTransportDaemonAndExtractionErrorsArePreservedAndRecover)
{
    auto created = factory.CreateCsrGenerationContext(Config());
    ASSERT_TRUE(created.has_value());
    ASSERT_TRUE(created.value()->SetSubjectDn("CN=device").has_value());
    ASSERT_TRUE(created.value()->AddExtension({"2.5.29.14", false, "hash"}).has_value());
    connection->public_key_info = PublicKeyInfo();
    ASSERT_FALSE(connection->public_key_info.empty());
    transcoder->fail_output = true;
    auto failed = created.value()->Generate();
    ASSERT_FALSE(failed.has_value());
    EXPECT_EQ(*failed.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kAllocationFailed));
    EXPECT_EQ(connection->public_info_queries, 0U);
    transcoder->fail_output = false;
    connection->transport_error = CryptoErrorCode::kOperationTimedOut;
    failed = created.value()->Generate();
    ASSERT_FALSE(failed.has_value());
    EXPECT_EQ(*failed.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kOperationTimedOut));
    connection->transport_error.reset();
    connection->daemon_error = CryptoErrorCode::kKeyOperationNotPermitted;
    failed = created.value()->Generate();
    ASSERT_FALSE(failed.has_value());
    EXPECT_EQ(*failed.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kKeyOperationNotPermitted));
    connection->daemon_error = static_cast<CryptoErrorCode>(0U);
    transcoder->fail_extract = true;
    failed = created.value()->Generate();
    ASSERT_FALSE(failed.has_value());
    EXPECT_EQ(*failed.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kInternalError));
    EXPECT_EQ(connection->generates, 3U);
    EXPECT_EQ(transcoder->input_shm_acquisitions, 4U);
    transcoder->fail_extract = false;
    ASSERT_TRUE(created.value()->Generate().has_value());
    EXPECT_EQ(connection->public_info_queries, 0U);
    EXPECT_EQ(connection->generates, 4U);
}

TEST_F(CsrContextTest, NativeGenerationRejectsMalformedResponsesAndWireCountsBeforeExtractionAndRecovers)
{
    auto created = factory.CreateCsrGenerationContext(Config());
    ASSERT_TRUE(created.has_value());
    ASSERT_TRUE(created.value()->SetSubjectDn("CN=device").has_value());
    ASSERT_TRUE(created.value()->AddExtension({"2.5.29.14", false, "hash"}).has_value());
    connection->public_key_info = PublicKeyInfo();
    ASSERT_FALSE(connection->public_key_info.empty());
    for (const uint64_t count : {uint64_t{0U},
                                 static_cast<uint64_t>(csr::kMaxDerBytes + 1U),
                                 (uint64_t{1U} << 32U) + 1U,
                                 std::numeric_limits<uint64_t>::max()})
    {
        connection->written_count = count;
        auto failed = created.value()->Generate();
        ASSERT_FALSE(failed.has_value());
        EXPECT_EQ(*failed.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kOperationFailed));
        EXPECT_EQ(transcoder->extractions, 0U);
    }
    connection->written_count.reset();
    for (bool* flag : {&connection->wrong_type,
                       &connection->wrong_actor,
                       &connection->wrong_action,
                       &connection->extra_parameter,
                       &connection->extra_operation,
                       &connection->missing_parameter,
                       &connection->missing_operation})
    {
        *flag = true;
        auto failed = created.value()->Generate();
        ASSERT_FALSE(failed.has_value());
        EXPECT_EQ(*failed.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kOperationFailed));
        EXPECT_EQ(transcoder->extractions, 0U);
        *flag = false;
    }
    EXPECT_EQ(connection->generates, 11U);
    EXPECT_EQ(transcoder->input_shm_acquisitions, 11U);
    ASSERT_TRUE(created.value()->Generate().has_value());
    EXPECT_EQ(connection->generates, 12U);
    EXPECT_EQ(transcoder->extractions, 1U);
}

TEST_F(CsrContextTest, DaemonRejectsInvalidPublicContextAndClientRejectsExtractionSizesAndRecovers)
{
    auto created = factory.CreateCsrGenerationContext(Config());
    ASSERT_TRUE(created.has_value());
    ASSERT_TRUE(created.value()->SetSubjectDn("CN=device").has_value());
    ASSERT_TRUE(created.value()->AddExtension({"2.5.29.14", false, "hash"}).has_value());
    const auto spki = PublicKeyInfo();
    ASSERT_FALSE(spki.empty());
    connection->public_key_info = spki;
    for (const std::size_t count : {std::size_t{0U}, csr::kMaxDerBytes + 1U})
    {
        transcoder->extracted_count = count;
        auto failed = created.value()->Generate();
        ASSERT_FALSE(failed.has_value());
        EXPECT_EQ(*failed.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kOperationFailed));
    }
    transcoder->extracted_count.reset();
    connection->public_key_info.clear();
    EXPECT_FALSE(created.value()->Generate().has_value());
    connection->public_key_info.resize(csr::kMaxDerBytes + 1U);
    EXPECT_FALSE(created.value()->Generate().has_value());
    connection->public_key_info = connection->der;
    auto failed = created.value()->Generate();
    ASSERT_FALSE(failed.has_value());
    EXPECT_EQ(*failed.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kInvalidArgument));
    connection->public_key_info = spki;
    connection->public_key_info.push_back(0U);
    failed = created.value()->Generate();
    ASSERT_FALSE(failed.has_value());
    EXPECT_EQ(*failed.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kInvalidArgument));
    EXPECT_EQ(connection->generates, 6U);
    EXPECT_EQ(transcoder->input_shm_acquisitions, 6U);
    connection->public_key_info = spki;
    ASSERT_TRUE(created.value()->Generate().has_value());
    EXPECT_EQ(connection->generates, 7U);
}

TEST_F(CsrContextTest, InProcessInlineOutputWorksForNativeGenerationAndKeyDependentExtensions)
{
    auto created = factory.CreateCsrGenerationContext(Config());
    ASSERT_TRUE(created.has_value());
    ASSERT_TRUE(created.value()->SetSubjectDn("CN=device").has_value());
    transcoder->inline_output = true;
    ASSERT_TRUE(created.value()->Generate().has_value());
    EXPECT_EQ(connection->public_info_queries, 0U);
    ASSERT_TRUE(created.value()->AddExtension({"2.5.29.14", false, "hash"}).has_value());
    connection->public_key_info = PublicKeyInfo();
    ASSERT_FALSE(connection->public_key_info.empty());
    auto generated = created.value()->Generate();
    ASSERT_TRUE(generated.has_value());
    std::vector<uint8_t> der(generated.value()->GetEncodedCsrLength());
    ASSERT_TRUE(generated.value()->GetEncodedCsr(der).has_value());
    EXPECT_EQ(der, connection->der);
    EXPECT_EQ(connection->public_info_queries, 0U);
    EXPECT_EQ(connection->generates, 2U);
    EXPECT_EQ(transcoder->extractions, 2U);
    connection->wrong_type = true;
    EXPECT_FALSE(created.value()->Generate().has_value());
    connection->wrong_type = false;
    connection->public_key_info.clear();
    EXPECT_FALSE(created.value()->Generate().has_value());
    connection->public_key_info.resize(csr::kMaxDerBytes + 1U);
    auto failed = created.value()->Generate();
    ASSERT_FALSE(failed.has_value());
    EXPECT_EQ(*failed.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kInvalidArgument));
    EXPECT_EQ(connection->generates, 5U);
    connection->public_key_info = PublicKeyInfo();
    EXPECT_TRUE(created.value()->Generate().has_value());
}

TEST_F(CsrContextTest, OutputExtractionErrorsArePreservedAndContextRecovers)
{
    auto created = factory.CreateCsrGenerationContext(Config());
    ASSERT_TRUE(created.has_value());
    ASSERT_TRUE(created.value()->SetSubjectDn("CN=device").has_value());
    transcoder->fail_extract = true;
    auto failed = created.value()->Generate();
    ASSERT_FALSE(failed.has_value());
    EXPECT_EQ(*failed.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kInternalError));
    transcoder->fail_extract = false;
    EXPECT_TRUE(created.value()->Generate().has_value());
}

TEST_F(CsrContextTest, RejectsInvalidWireCountsBeforeOutputExtractionAndRecovers)
{
    auto created = factory.CreateCsrGenerationContext(Config());
    ASSERT_TRUE(created.has_value());
    ASSERT_TRUE(created.value()->SetSubjectDn("CN=device").has_value());
    for (const uint64_t count : {uint64_t{0U},
                                 static_cast<uint64_t>(csr::kMaxDerBytes + 1U),
                                 (uint64_t{1U} << 32U) + 1U,
                                 std::numeric_limits<uint64_t>::max()})
    {
        connection->written_count = count;
        auto failed = created.value()->Generate();
        ASSERT_FALSE(failed.has_value());
        EXPECT_EQ(*failed.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kOperationFailed));
        EXPECT_EQ(transcoder->extractions, 0U);
    }
    connection->written_count.reset();
    EXPECT_TRUE(created.value()->Generate().has_value());
    EXPECT_EQ(transcoder->extractions, 1U);
}

TEST_F(CsrContextTest, RejectsInvalidExtractedGenerationSizesAndRecovers)
{
    auto created = factory.CreateCsrGenerationContext(Config());
    ASSERT_TRUE(created.has_value());
    ASSERT_TRUE(created.value()->SetSubjectDn("CN=device").has_value());
    for (const std::size_t count : {std::size_t{0U}, csr::kMaxDerBytes + 1U})
    {
        transcoder->extracted_count = count;
        auto failed = created.value()->Generate();
        ASSERT_FALSE(failed.has_value());
        EXPECT_EQ(*failed.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kOperationFailed));
    }
    transcoder->extracted_count.reset();
    EXPECT_TRUE(created.value()->Generate().has_value());
    EXPECT_EQ(connection->public_info_queries, 0U);
    EXPECT_EQ(transcoder->extractions, 3U);
}

TEST_F(CsrContextTest, PreservesTransportAndDaemonErrorsAndRejectsMalformedResponses)
{
    auto created = factory.CreateCsrGenerationContext(Config());
    ASSERT_TRUE(created.has_value());
    ASSERT_TRUE(created.value()->SetSubjectDn("CN=device").has_value());
    connection->transport_error = CryptoErrorCode::kOperationTimedOut;
    auto failed = created.value()->Generate();
    ASSERT_FALSE(failed.has_value());
    EXPECT_EQ(*failed.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kOperationTimedOut));
    connection->transport_error.reset();
    connection->daemon_error = CryptoErrorCode::kKeyOperationNotPermitted;
    failed = created.value()->Generate();
    ASSERT_FALSE(failed.has_value());
    EXPECT_EQ(*failed.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kKeyOperationNotPermitted));
    connection->daemon_error = static_cast<CryptoErrorCode>(0U);
    for (bool* flag : {&connection->wrong_type,
                       &connection->wrong_actor,
                       &connection->wrong_action,
                       &connection->extra_parameter,
                       &connection->extra_operation,
                       &connection->missing_parameter,
                       &connection->missing_operation})
    {
        *flag = true;
        EXPECT_FALSE(created.value()->Generate().has_value());
        *flag = false;
    }
    EXPECT_EQ(transcoder->extractions, 0U);
    connection->der.clear();
    EXPECT_FALSE(created.value()->Generate().has_value());
    connection->der.resize(csr::kMaxDerBytes + 1U);
    EXPECT_FALSE(created.value()->Generate().has_value());
}

TEST_F(CsrContextTest, ExplicitProcessingClientRejectsMalformedWireShapesAndCountsAndRecovers)
{
    CsrProcessingClient remote{connection, transcoder};
    auto subject = CsrSubject::FromDn(remote, "CN=remote,O=SCORE,C=DE");
    ASSERT_TRUE(subject.has_value());
    ASSERT_EQ(subject->Attributes().size(), 3U);
    EXPECT_EQ(connection->generates, 0U);
    EXPECT_FALSE(CsrSubject::FromDn(remote, "CN=malformed,").has_value());
    for (bool* flag : {&connection->processing_extra_field,
                       &connection->processing_wrong_action,
                       &connection->processing_trailing_data,
                       &connection->wrong_type,
                       &connection->wrong_actor,
                       &connection->wrong_action,
                       &connection->extra_parameter,
                       &connection->missing_parameter,
                       &connection->extra_operation,
                       &connection->missing_operation})
    {
        *flag = true;
        EXPECT_FALSE(CsrSubject::FromDn(remote, "CN=remote").has_value());
        *flag = false;
    }
    for (const uint64_t count : {uint64_t{0U},
                                 static_cast<uint64_t>(score::crypto::csr::wire::kMaxWireBytes + 1U),
                                 (uint64_t{1U} << 32U) + 1U,
                                 std::numeric_limits<uint64_t>::max()})
    {
        connection->written_count = count;
        EXPECT_FALSE(CsrSubject::FromDn(remote, "CN=remote").has_value());
    }
    connection->written_count.reset();
    connection->transport_error = CryptoErrorCode::kOperationTimedOut;
    auto result = CsrSubject::FromDn(remote, "CN=remote");
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(*result.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kOperationTimedOut));
    connection->transport_error.reset();
    connection->daemon_error = CryptoErrorCode::kUnsupportedOperation;
    result = CsrSubject::FromDn(remote, "CN=remote");
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(*result.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kUnsupportedOperation));
    connection->daemon_error = static_cast<CryptoErrorCode>(0U);
    transcoder->inline_output = true;
    EXPECT_TRUE(CsrSubject::FromDn(remote, "CN=remote").has_value());
    EXPECT_EQ(connection->generates, 0U);
}
}  // namespace
}  // namespace score::crypto

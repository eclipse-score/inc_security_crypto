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

// Source: fea_um_crypto_1 1f4b0daa (catalog-based key generation).
// Original path: score/crypto/src/daemon/mediator/csr_context_test.cpp.
// Adaptation: explicitly leave the target's additional cert_service unset.
#include "score/crypto/src/common/csr_der.hpp"
#include "score/crypto/src/common/csr_wire.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/common/context_types.hpp"
#include "score/crypto/src/daemon/data_manager/data_manager.hpp"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"
#include "score/crypto/src/daemon/mediator/src/mediator_impl.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/csr_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/provider_openssl.hpp"

#include <gtest/gtest.h>
#include <openssl/x509.h>
#include <algorithm>
#include <vector>

namespace score::crypto::daemon::mediator
{
namespace
{
namespace cp = control_plane;
namespace dm = data_manager;
namespace km = key_management;
namespace csr = provider::handler::csr_handler_operations;
namespace codec = ::score::crypto::csr::der;
using Permission = score::crypto::KeyOperationPermission;
using Error = score::crypto::CryptoErrorCode;
constexpr dm::ClientId kClient = 42U;

class CsrContextTest : public ::testing::Test
{
  protected:
    static void SetUpTestSuite()
    {
        manager_ = std::make_shared<provider::ProviderManager>(config::ProviderInitConfig{});
        openssl_ = std::make_shared<provider::score_provider::openssl::OpenSSL>();
        ASSERT_TRUE(manager_->RegisterProvider("OPENSSL", openssl_, common::CryptoProviderType::SOFTWARE));
        ASSERT_TRUE(manager_->Initialize());
    }

    static void TearDownTestSuite()
    {
        manager_.reset();
        openssl_.reset();
    }

    void SetUp() override
    {
        data_ = std::make_shared<dm::DataManager>();
        keys_ = std::make_shared<km::KeyManagementService>(data_, manager_, std::make_shared<km::SlotRegistry>());
        openssl_->SetKeyManagementService(keys_);
        auto root = data_->addNode(kClient, std::make_shared<dm::DataNode>());
        ASSERT_TRUE(root.has_value());
        root_ = root.value();
        mediator_ = std::make_unique<MediatorImpl>(MediatorDependencies{data_, manager_, keys_, nullptr, nullptr});
    }

    void TearDown() override
    {
        EXPECT_TRUE(data_->deleteClientNodes(kClient).has_value());
        mediator_.reset();
        // Break the fixture's provider/service/manager ownership cycle.
        openssl_->SetKeyManagementService(nullptr);
    }

    dm::DataNodeId Key(Permission permission)
    {
        km::KeyGenerationRequest request;
        request.algorithm = ::score::crypto::GetAlgorithmDescriptor("ECDSA-P256").value();
        request.permissions = permission;
        auto key = openssl_->GetKeyFactory()->GenerateKey(request);
        EXPECT_TRUE(key.has_value());
        if (!key.has_value())
        {
            return 0U;
        }
        km::KeyRegistrationParams registration;
        registration.client_id = kClient;
        registration.parent_id = root_;
        registration.provider_id = openssl_->GetProviderId();
        auto registered = keys_->RegisterKeyMaterial(registration, std::move(key.value()));
        EXPECT_TRUE(registered.has_value());
        return registered.has_value() ? registered->node_id : 0U;
    }

    cp::SingleOperationResponse Call(dm::DataNodeId node,
                                     common::OperationIdentifier operation,
                                     common::RequestParameters params)
    {
        cp::ControlRequest request{};
        request.client_id = kClient;
        request.data_node_id = node;
        request.operation.operations.push_back({operation, std::move(params)});
        auto response = mediator_->processRequest(request);
        EXPECT_EQ(response.operation.operations.size(), 1U);
        return response.operation.operations.empty() ? cp::SingleOperationResponse{}
                                                     : std::move(response.operation.operations.front());
    }

    cp::SingleOperationResponse Create(common::RequestParameter key)
    {
        return Call(
            root_,
            {common::actors::OP_ACTOR_MEDIATOR, operations::CTX_CREATE},
            {common::context_types::kCsrGeneration, std::string_view{"ECDSA-P256-SHA256"}, common::NoParam{}, key});
    }

    std::shared_ptr<dm::DataManager> data_;
    inline static provider::ProviderManager::Sptr manager_;
    inline static std::shared_ptr<provider::score_provider::openssl::OpenSSL> openssl_;
    km::KeyManagementService::Sptr keys_;
    std::unique_ptr<MediatorImpl> mediator_;
    dm::DataNodeId root_{};
};

TEST_F(CsrContextTest, HandleBoundContextGeneratesVerifiedDerAndCloses)
{
    const auto key = Key(Permission::kSign);
    ASSERT_NE(key, 0U);
    auto created = Create(key);
    ASSERT_EQ(created.result, 0U);
    ASSERT_EQ(created.parameters.size(), 1U);
    const auto context = std::get<std::uint64_t>(created.parameters[0]);
    // Drop the caller's key reference: the context must retain its binding.
    ASSERT_TRUE(keys_->ReleaseKeyMaterial(kClient, key).has_value());
    const auto input =
        codec::EncodeParameters({{"2.5.4.3", "daemon-device"}}, {{"2.5.29.17", false, "DNS:daemon.example"}}, "");
    ASSERT_TRUE(input.has_value());
    auto generated = Call(context,
                          {common::actors::OP_ACTOR_CSR_HANDLER, csr::CSR_GENERATE},
                          {score::cpp::span<const std::uint8_t>{input->data(), input->size()}});
    ASSERT_EQ(generated.result, 0U);
    ASSERT_EQ(generated.parameters.size(), 1U);
    const auto* der = std::get_if<common::OwnedBuffer>(&generated.parameters[0]);
    ASSERT_NE(der, nullptr);
    const auto* cursor = der->data();
    std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)> req{
        d2i_X509_REQ(nullptr, &cursor, static_cast<long>(der->size())), X509_REQ_free};
    ASSERT_NE(req, nullptr);
    EXPECT_EQ(X509_REQ_verify(req.get(), X509_REQ_get0_pubkey(req.get())), 1);
    EXPECT_EQ(cursor, der->data() + der->size());
    EXPECT_EQ(Call(context, {common::actors::OP_ACTOR_MEDIATOR, operations::CTX_CLOSE}, {}).result, 0U);
    EXPECT_FALSE(data_->getNodeAccessor(kClient, context).has_value());
}

TEST_F(CsrContextTest, BoundContextWritesDerToResolvedOutputAndReturnsOnlyLength)
{
    const auto key = Key(Permission::kSign);
    ASSERT_NE(key, 0U);
    auto created = Create(key);
    ASSERT_EQ(created.result, 0U);
    ASSERT_EQ(created.parameters.size(), 1U);
    const auto context = std::get<std::uint64_t>(created.parameters[0]);
    ASSERT_TRUE(keys_->ReleaseKeyMaterial(kClient, key).has_value());
    const auto input = codec::EncodeParameters({{"2.5.4.3", "daemon-device"}}, {}, "");
    ASSERT_TRUE(input.has_value());
    std::vector<std::uint8_t> guarded(csr::kMaxDerBytes + 8U, 0xA5U);
    const auto der = score::cpp::span<std::uint8_t>{guarded.data() + 4U, csr::kMaxDerBytes};
    // At mediator dispatch the SHM handler has already resolved descriptors.
    auto generated = Call(context,
                          {common::actors::OP_ACTOR_CSR_HANDLER, csr::CSR_GENERATE},
                          {score::cpp::span<const std::uint8_t>{input->data(), input->size()}, der});
    ASSERT_EQ(generated.result, 0U);
    ASSERT_EQ(generated.parameters.size(), 1U);
    const auto* written = std::get_if<std::uint64_t>(&generated.parameters[0]);
    ASSERT_NE(written, nullptr);
    ASSERT_GT(*written, 0U);
    ASSERT_LE(*written, der.size());
    const auto* cursor = der.data();
    std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)> req{d2i_X509_REQ(nullptr, &cursor, static_cast<long>(*written)),
                                                            X509_REQ_free};
    ASSERT_NE(req, nullptr);
    EXPECT_EQ(cursor, der.data() + *written);
    EXPECT_EQ(X509_REQ_verify(req.get(), X509_REQ_get0_pubkey(req.get())), 1);
    EXPECT_TRUE(std::all_of(guarded.begin(), guarded.begin() + 4U, [](std::uint8_t byte) {
        return byte == 0xA5U;
    }));
    EXPECT_TRUE(
        std::all_of(guarded.begin() + 4U + static_cast<std::size_t>(*written), guarded.end(), [](std::uint8_t byte) {
            return byte == 0xA5U;
        }));
    EXPECT_EQ(Call(context, {common::actors::OP_ACTOR_MEDIATOR, operations::CTX_CLOSE}, {}).result, 0U);
    EXPECT_FALSE(data_->getNodeAccessor(kClient, context).has_value());
}

TEST_F(CsrContextTest, ContextCreationRequiresSignPermissionAndValidKeyHandle)
{
    const auto denied_key = Key(Permission::kVerify);
    ASSERT_NE(denied_key, 0U);
    EXPECT_EQ(Create(denied_key).result, static_cast<cp::protocol::OperationResult>(Error::kKeyOperationNotPermitted));
    EXPECT_EQ(Create(common::NoParam{}).result, static_cast<cp::protocol::OperationResult>(Error::kInvalidArgument));
    EXPECT_EQ(Create(std::uint64_t{0U}).result, static_cast<cp::protocol::OperationResult>(Error::kInvalidArgument));
    EXPECT_NE(Create(std::uint64_t{999999U}).result, 0U);
    EXPECT_NE(Create(std::uint32_t{1U}).result, 0U);
    // Refusing one creation must not prevent a subsequent authorized creation.
    EXPECT_EQ(Create(Key(Permission::kSign)).result, 0U);
}

TEST_F(CsrContextTest, KeylessProcessingUsesOwnedConnectionAndDoesNotAuthorizeSigning)
{
    namespace wire = ::score::crypto::csr::wire;
    wire::Document document;
    document.action = wire::Action::FromDn;
    document.text = "CN=remote-device,O=SCORE,C=DE";
    auto encoded = wire::Encode(document);
    ASSERT_TRUE(encoded.has_value());
    std::vector<uint8_t> output(wire::kMaxWireBytes, 0xA5U);
    auto result = Call(root_,
                       operations::ProcessCsr(),
                       {score::cpp::span<const uint8_t>{encoded->data(), encoded->size()},
                        score::cpp::span<uint8_t>{output.data(), output.size()}});
    ASSERT_EQ(result.result, 0U);
    ASSERT_EQ(result.parameters.size(), 1U);
    const auto count = std::get<uint64_t>(result.parameters[0]);
    ASSERT_GT(count, 0U);
    ASSERT_LE(count, output.size());
    auto decoded = wire::Decode({output.data(), static_cast<std::size_t>(count)});
    ASSERT_TRUE(decoded.has_value());
    EXPECT_TRUE(wire::ResponseShape(decoded.value()));
    ASSERT_EQ(decoded->subject.size(), 3U);
    EXPECT_EQ(decoded->subject[0]->value, "remote-device");
    EXPECT_TRUE(std::all_of(output.begin() + static_cast<std::size_t>(count), output.end(), [](uint8_t value) {
        return value == 0xA5U;
    }));

    // A foreign authenticated client cannot name this connection root.
    cp::ControlRequest foreign{};
    foreign.client_id = kClient + 1U;
    foreign.data_node_id = root_;
    foreign.operation.operations.push_back({operations::ProcessCsr(),
                                            {score::cpp::span<const uint8_t>{encoded->data(), encoded->size()},
                                             score::cpp::span<uint8_t>{output.data(), output.size()}}});
    auto denied = mediator_->processRequest(foreign);
    ASSERT_EQ(denied.operation.operations.size(), 1U);
    EXPECT_NE(denied.operation.operations[0].result, 0U);

    // Processing cannot be routed through a keyed context or invoke signing.
    auto created = Create(Key(Permission::kSign));
    ASSERT_EQ(created.result, 0U);
    const auto context = std::get<uint64_t>(created.parameters[0]);
    EXPECT_NE(Call(context,
                   operations::ProcessCsr(),
                   {score::cpp::span<const uint8_t>{encoded->data(), encoded->size()},
                    score::cpp::span<uint8_t>{output.data(), output.size()}})
                  .result,
              0U);
    document.action = wire::Action::Generate;
    encoded = wire::Encode(document);
    ASSERT_TRUE(encoded.has_value());
    std::fill(output.begin(), output.end(), 0xA5U);
    EXPECT_NE(Call(root_,
                   operations::ProcessCsr(),
                   {score::cpp::span<const uint8_t>{encoded->data(), encoded->size()},
                    score::cpp::span<uint8_t>{output.data(), output.size()}})
                  .result,
              0U);
    EXPECT_TRUE(std::all_of(output.begin(), output.end(), [](uint8_t value) {
        return value == 0xA5U;
    }));
}

TEST_F(CsrContextTest, NativeGenerationPreservesBindingAndCannotBeDecodedAsLegacy)
{
    namespace wire = ::score::crypto::csr::wire;
    const auto key = Key(Permission::kSign);
    auto created = Create(key);
    ASSERT_EQ(created.result, 0U);
    const auto context = std::get<uint64_t>(created.parameters[0]);
    ASSERT_TRUE(keys_->ReleaseKeyMaterial(kClient, key).has_value());
    wire::Document document;
    document.action = wire::Action::Generate;
    auto subject = std::make_unique<wire::fb::EntryT>();
    subject->oid = "2.5.4.3";
    subject->value = "native-device";
    document.subject.push_back(std::move(subject));
    auto extension = std::make_unique<wire::fb::ExtensionT>();
    extension->oid = "2.5.29.14";
    extension->value = "hash";
    document.extensions.push_back(std::move(extension));
    auto encoded = wire::Encode(document);
    ASSERT_TRUE(encoded.has_value());
    auto generated = Call(context,
                          {common::actors::OP_ACTOR_CSR_HANDLER, csr::CSR_GENERATE_NATIVE},
                          {score::cpp::span<const uint8_t>{encoded->data(), encoded->size()}});
    ASSERT_EQ(generated.result, 0U);
    const auto& der = std::get<common::OwnedBuffer>(generated.parameters[0]);
    const auto* cursor = der.data();
    std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)> request{
        d2i_X509_REQ(nullptr, &cursor, static_cast<long>(der.size())), X509_REQ_free};
    ASSERT_TRUE(request);
    EXPECT_EQ(cursor, der.data() + der.size());
    EXPECT_EQ(X509_REQ_verify(request.get(), X509_REQ_get0_pubkey(request.get())), 1);
    EXPECT_NE(Call(context,
                   {common::actors::OP_ACTOR_CSR_HANDLER, csr::CSR_GENERATE},
                   {score::cpp::span<const uint8_t>{encoded->data(), encoded->size()}})
                  .result,
              0U);
    auto legacy = codec::EncodeParameters({{"2.5.4.3", "legacy"}}, {}, "");
    ASSERT_TRUE(legacy.has_value());
    EXPECT_NE(Call(context,
                   {common::actors::OP_ACTOR_CSR_HANDLER, csr::CSR_GENERATE_NATIVE},
                   {score::cpp::span<const uint8_t>{legacy->data(), legacy->size()}})
                  .result,
              0U);
}
}  // namespace
}  // namespace score::crypto::daemon::mediator

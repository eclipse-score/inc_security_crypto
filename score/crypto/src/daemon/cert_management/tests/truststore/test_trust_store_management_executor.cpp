/*******************************************************************************
 *
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
 *******************************************************************************
 */

// Component-level tests for the CERT:TRUST_STORE executor and context handler.
//
// The executor runs against a real CertManagementService, TrustStoreManager, slot manager, and OpenSSL parser on a
// per-test temporary directory. The member slot is populated through the trust-store manager so that CRL import can
// validate the CRL against the certificate the slot holds. Test vectors come from
// score/tests/test_vectors/certificate/basic/.

#include "score/crypto/src/daemon/cert_management/context/trust_store/context_handler.hpp"
#include "score/crypto/src/daemon/cert_management/context/trust_store/executor.hpp"
#include "score/crypto/src/daemon/cert_management/core/cert_management_service.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_management_operations.hpp"
#include "score/crypto/src/daemon/cert_management/slot/cert_slot_manager.hpp"
#include "score/crypto/src/daemon/cert_management/slot/slot_handler_factory.hpp"
#include "score/crypto/src/daemon/cert_management/truststore/trust_store_manager.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/common/storage/kv/kv_deployment_writer.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/data_manager/data_manager.hpp"
#include "score/crypto/src/daemon/provider/cert_management/i_cert_parser.hpp"
#include "score/crypto/src/daemon/provider/provider_manager.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/cert_management/openssl_cert_parser.hpp"
#include "score/tests/utility/test_utility.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

namespace cert = score::crypto::daemon::cert_management;
namespace common = score::crypto::daemon::common;
namespace dm = score::crypto::daemon::data_manager;
namespace config = score::crypto::daemon::config;
namespace openssl_ns = score::crypto::daemon::provider::score_provider::openssl;
namespace provider = score::crypto::daemon::provider;
namespace storage = score::crypto::daemon::common::storage;
namespace ops = score::crypto::daemon::cert_management::operations;
using Error = common::DaemonErrorCode;

/// Client 1 carries uid 0, which the trust-store and slot access policies below allow.
constexpr dm::ClientId kClient{1U};
constexpr std::string_view kStoreName{"mutable-store"};
constexpr std::string_view kSlotName{"exclusive-anchor"};
/// An action code that no trust-store operation uses.
constexpr common::OperationAction kUnassignedAction{0xC7U};

class OpenSslParserProvider final : public provider::IProvider
{
  public:
    explicit OpenSslParserProvider(provider::cert_management::ICertParser::Sptr parser) : m_parser{std::move(parser)} {}

    bool Initialize(const provider::ProviderInitContext& context) override
    {
        m_provider_id = context.numeric_id;
        m_provider_name = context.name;
        m_initialized = true;
        return true;
    }

    void Shutdown() override
    {
        m_initialized = false;
    }

    [[nodiscard]] bool IsInitialized() const override
    {
        return m_initialized;
    }

    common::ProviderId GetProviderId() const override
    {
        return m_provider_id;
    }

    const common::ProviderName& GetProviderName() const override
    {
        return m_provider_name;
    }

    provider::cert_management::ICertParser::Sptr GetCertParser() override
    {
        return m_parser;
    }

    [[nodiscard]] common::ProviderCapability GetProviderCapabilities() override
    {
        return common::ProviderCapability::kCertManagement;
    }

  private:
    provider::cert_management::ICertParser::Sptr m_parser;
    common::ProviderId m_provider_id{common::kInvalidProviderId};
    common::ProviderName m_provider_name;
    bool m_initialized{false};
};

std::vector<std::uint8_t> ReadFile(const std::filesystem::path& path)
{
    std::ifstream file(path, std::ios::binary);
    return std::vector<std::uint8_t>{std::istreambuf_iterator<char>(file), {}};
}

common::OperationIdentifier OperationFor(common::OperationAction action)
{
    return common::OperationIdentifier{.operationActor = common::actors::OP_ACTOR_CERT_MANAGEMENT,
                                       .operationAction = action};
}

class TrustStoreManagementExecutorTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        ::tests::utility::ConfigureTestLogging();
        m_dir = ::tests::utility::TempDirectory("score_ts_mgmt_executor");
        std::filesystem::remove_all(m_dir);
        std::filesystem::create_directories(m_dir);

        const auto root_source =
            ::tests::utility::TestVectorPath("score/tests/test_vectors/certificate/basic/certificate.pem");
        m_root_cert_path = m_dir / "root_ca.pem";
        ASSERT_TRUE(std::filesystem::copy_file(
            root_source, m_root_cert_path, std::filesystem::copy_options::overwrite_existing));
        m_crl_bytes = ReadFile(
            ::tests::utility::TestVectorPath("score/tests/test_vectors/certificate/basic/certificate.crl.pem"));
        ASSERT_FALSE(m_crl_bytes.empty());

        m_parser = std::make_shared<openssl_ns::OpenSslCertParser>(common::ProviderId{0U});
        m_provider_manager = std::make_shared<provider::ProviderManager>(config::ProviderInitConfig{});
        ASSERT_TRUE(m_provider_manager->RegisterProvider(
            "OPENSSL", std::make_shared<OpenSslParserProvider>(m_parser), common::CryptoProviderType::SOFTWARE));
        ASSERT_TRUE(m_provider_manager->Initialize());

        // The member slot starts empty; AddMember below writes the certificate to its cert_path.
        const auto slot_descriptor = m_dir / "exclusive.kv";
        const auto slot_cert = m_dir / "exclusive.pem";
        storage::DeploymentDescriptor descriptor;
        descriptor.Set("certificate", "cert_path", slot_cert.string());
        descriptor.Set("certificate", "cert_format", "pem");
        ASSERT_TRUE(storage::KvDeploymentWriter{}.Write(slot_descriptor.string(), descriptor).has_value());

        cert::CertSlotConfig slot_config;
        slot_config.slot_name = std::string{kSlotName};
        slot_config.storage_backend = "DEFAULT";
        slot_config.deployment_path = slot_descriptor.string();
        slot_config.deployment_format = "kv";
        slot_config.access_policy.allowed_write_uids = {0U};

        m_registry = std::make_shared<cert::CertSlotRegistry>();
        static_cast<void>(m_registry->RegisterSlot(slot_config));
        m_slot_manager = std::make_shared<cert::CertSlotManager>(
            m_registry, std::make_shared<cert::SlotHandlerFactory>(m_provider_manager));

        cert::TrustStoreConfig store_config;
        store_config.store_name = std::string{kStoreName};
        store_config.access_policy.allowed_write_uids = {0U};
        store_config.members.push_back(
            cert::TrustStoreMemberConfig{std::string{kSlotName}, cert::TrustStoreMemberKind::kExclusiveMutable});
        m_trust_store_manager = std::make_shared<cert::TrustStoreManager>();
        ASSERT_TRUE(m_trust_store_manager->Load({store_config}, m_registry, m_slot_manager).has_value());
        m_trust_store_manager->RegisterAppResource(0U, std::string{kStoreName}, std::string{kStoreName});

        m_data_manager = std::make_shared<dm::DataManager>();
        m_service = std::make_shared<cert::CertManagementService>(
            m_data_manager, m_registry, m_trust_store_manager, m_slot_manager);
        m_executor = std::make_shared<cert::TrustStoreManagementExecutor>(m_parser, m_service);

        // Populate the exclusive member with the basic test certificate through the manager.
        const auto root_bytes = ReadFile(m_root_cert_path);
        const auto root =
            m_parser->ParseCertificate(root_bytes.data(), root_bytes.size(), score::crypto::FormatType::kPem);
        ASSERT_TRUE(root.has_value());
        const auto handle = m_trust_store_manager->ResolveByName(std::string{kStoreName});
        ASSERT_TRUE(handle.has_value());
        m_trust_store_handle = handle.value();
        ASSERT_TRUE(m_trust_store_manager->AddMember(m_trust_store_handle, root.value(), kClient).has_value());

        const auto members = m_trust_store_manager->GetMemberSlotHandles(m_trust_store_handle);
        ASSERT_TRUE(members.has_value());
        ASSERT_EQ(members.value().size(), 1U);
        m_member_slot = members.value().front();

        const auto trust_store_node = m_service->ResolveTrustStoreNode(std::string{kStoreName}, kClient);
        ASSERT_TRUE(trust_store_node.has_value());
        m_trust_store_node = static_cast<std::uint64_t>(trust_store_node.value());
        const auto member_node = m_service->ResolveCertSlotNode(m_member_slot, kClient);
        ASSERT_TRUE(member_node.has_value());
        m_member_node = static_cast<std::uint64_t>(member_node.value());

        m_ctx.client_id = kClient;
        m_ctx.context_node_id = 0U;
    }

    void TearDown() override
    {
        static_cast<void>(m_data_manager->deleteClientNodes(kClient));
        std::error_code ec;
        std::filesystem::remove_all(m_dir, ec);
    }

    score::crypto::Expected<common::ResponseParameters, Error> Run(common::OperationAction action,
                                                                   common::RequestParameters request)
    {
        return m_executor->Execute(m_ctx, OperationFor(action), request);
    }

    /// Import the basic test CRL into the member slot through the executor.
    void ImportValidCrl()
    {
        common::RequestParameters request{
            std::uint64_t{m_trust_store_node},
            std::uint64_t{m_member_node},
            std::uint8_t{static_cast<std::uint8_t>(score::crypto::FormatType::kPem)},
            score::crypto::span<const std::uint8_t>{m_crl_bytes.data(), m_crl_bytes.size()}};
        ASSERT_TRUE(Run(ops::TRUST_STORE_IMPORT_CRL_FOR_MEMBER, request).has_value());
    }

    std::filesystem::path m_dir;
    std::filesystem::path m_root_cert_path;
    std::vector<std::uint8_t> m_crl_bytes;
    std::shared_ptr<openssl_ns::OpenSslCertParser> m_parser;
    provider::ProviderManager::Sptr m_provider_manager;
    cert::CertSlotRegistry::Sptr m_registry;
    cert::CertSlotManager::Sptr m_slot_manager;
    cert::TrustStoreManager::Sptr m_trust_store_manager;
    std::shared_ptr<dm::DataManager> m_data_manager;
    cert::CertManagementService::Sptr m_service;
    std::shared_ptr<cert::TrustStoreManagementExecutor> m_executor;
    cert::CertExecutionContext m_ctx{};
    cert::TrustStoreHandle m_trust_store_handle{};
    cert::CertSlotHandle m_member_slot{};
    std::uint64_t m_trust_store_node{0U};
    std::uint64_t m_member_node{0U};
};

TEST_F(TrustStoreManagementExecutorTest, UnassignedActionCode_IsUnsupportedOperation)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_mgmt__trust_stores");
    RecordProperty("Description", "An operation code outside the trust-store set is refused.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto result = Run(kUnassignedAction, {});

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kUnsupportedOperation);
}

TEST_F(TrustStoreManagementExecutorTest, AddMember_MissingParameters_ReturnsInsufficientParameters)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_mgmt__trust_stores");
    RecordProperty("Description", "Membership addition without its parameters is refused before any resolution.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto result = Run(ops::TRUST_STORE_ADD_CERT, {});

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kInsufficientParameters);
}

TEST_F(TrustStoreManagementExecutorTest, RemoveMember_FingerprintOfWrongLength_ReturnsInvalidArgument)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_mgmt__trust_stores");
    RecordProperty("Description",
                   "A removal fingerprint whose length is not the SHA-256 fingerprint length is refused.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const std::vector<std::uint8_t> short_fingerprint(31U, 0U);
    common::RequestParameters request{
        std::uint64_t{m_trust_store_node},
        score::crypto::span<const std::uint8_t>{short_fingerprint.data(), short_fingerprint.size()}};

    const auto result = Run(ops::TRUST_STORE_REMOVE_CERT, request);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kInvalidArgument);
}

TEST_F(TrustStoreManagementExecutorTest, EnableMember_UnknownTrustStoreNode_IsRejected)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_mgmt__trust_stores");
    RecordProperty("Description", "Enabling a member of a node that is not a trust store is refused.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    common::RequestParameters request{std::uint64_t{0U}, std::uint64_t{m_member_node}};

    const auto result = Run(ops::TRUST_STORE_ENABLE_CERT, request);

    EXPECT_FALSE(result.has_value());
}

TEST_F(TrustStoreManagementExecutorTest, ImportCrl_ValidCrl_StoresCrlOnMemberSlot)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_mgmt__trust_stores");
    RecordProperty("Description", "A CRL issued by the member certificate is stored on the exclusive member slot.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    ImportValidCrl();

    const auto has_crl = m_slot_manager->HasCrl(m_member_slot, kClient);
    ASSERT_TRUE(has_crl.has_value());
    EXPECT_TRUE(has_crl.value());
}

TEST_F(TrustStoreManagementExecutorTest, ImportCrl_RawFormat_IsInvalidArgument)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_mgmt__trust_stores");
    RecordProperty("Description", "A CRL whose encoding is neither DER nor PEM is refused and not stored.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    common::RequestParameters request{std::uint64_t{m_trust_store_node},
                                      std::uint64_t{m_member_node},
                                      std::uint8_t{static_cast<std::uint8_t>(score::crypto::FormatType::kRaw)},
                                      score::crypto::span<const std::uint8_t>{m_crl_bytes.data(), m_crl_bytes.size()}};

    const auto result = Run(ops::TRUST_STORE_IMPORT_CRL_FOR_MEMBER, request);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kInvalidArgument);
    const auto has_crl = m_slot_manager->HasCrl(m_member_slot, kClient);
    ASSERT_TRUE(has_crl.has_value());
    EXPECT_FALSE(has_crl.value());
}

TEST_F(TrustStoreManagementExecutorTest, ImportCrl_MalformedBytes_StoresNothing)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_mgmt__trust_stores");
    RecordProperty("Description", "CRL bytes that do not parse are refused and nothing is stored.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const std::vector<std::uint8_t> garbage{0xD0U, 0xD1U, 0xD2U};
    common::RequestParameters request{std::uint64_t{m_trust_store_node},
                                      std::uint64_t{m_member_node},
                                      std::uint8_t{static_cast<std::uint8_t>(score::crypto::FormatType::kPem)},
                                      score::crypto::span<const std::uint8_t>{garbage.data(), garbage.size()}};

    const auto result = Run(ops::TRUST_STORE_IMPORT_CRL_FOR_MEMBER, request);

    EXPECT_FALSE(result.has_value());
    const auto has_crl = m_slot_manager->HasCrl(m_member_slot, kClient);
    ASSERT_TRUE(has_crl.has_value());
    EXPECT_FALSE(has_crl.value());
}

TEST_F(TrustStoreManagementExecutorTest, DeleteCrl_RemovesStoredMemberCrl)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_mgmt__trust_stores");
    RecordProperty("Description", "Deleting a member CRL clears the CRL of the exclusive member slot.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    ImportValidCrl();
    common::RequestParameters request{std::uint64_t{m_trust_store_node}, std::uint64_t{m_member_node}};

    const auto result = Run(ops::TRUST_STORE_DELETE_CRL_FOR_MEMBER, request);

    ASSERT_TRUE(result.has_value());
    const auto has_crl = m_slot_manager->HasCrl(m_member_slot, kClient);
    ASSERT_TRUE(has_crl.has_value());
    EXPECT_FALSE(has_crl.value());
}

TEST_F(TrustStoreManagementExecutorTest, ContextHandler_RejectsOperationBeforeInitialization)
{
    cert::TrustStoreManagementContextHandler handler{m_executor};
    common::RequestParameters request{};

    const auto result = handler.Execute(OperationFor(ops::TRUST_STORE_ADD_CERT), request);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kInvalidOperation);
}

TEST_F(TrustStoreManagementExecutorTest, ContextHandler_RejectsSecondInitialization)
{
    cert::TrustStoreManagementContextHandler handler{m_executor};
    common::InitializationParams params{};
    params.client_id = kClient;
    params.context_node_id = 0U;

    ASSERT_TRUE(handler.InitializeContext(params).has_value());
    const auto second = handler.InitializeContext(params);

    ASSERT_FALSE(second.has_value());
    EXPECT_EQ(second.error(), Error::kInvalidOperation);
}

}  // namespace

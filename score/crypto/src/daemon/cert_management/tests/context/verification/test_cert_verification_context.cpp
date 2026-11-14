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

// Component-level tests for the CERT:VERIFICATION factory, executor, session, and context handler.
//
// The session runs against a real CertManagementService, TrustStoreManager, slot manager, and OpenSSL parser on a
// per-test temporary directory. The path validator is a recording fake: it captures each request the session builds and
// returns a canned result. Test vectors come from score/tests/test_vectors/certificate/basic/.

#include "score/crypto/src/daemon/cert_management/context/verification/context_factory.hpp"
#include "score/crypto/src/daemon/cert_management/context/verification/context_handler.hpp"
#include "score/crypto/src/daemon/cert_management/context/verification/executor.hpp"
#include "score/crypto/src/daemon/cert_management/context/verification/session.hpp"
#include "score/crypto/src/daemon/cert_management/core/cert_entry.hpp"
#include "score/crypto/src/daemon/cert_management/core/cert_management_service.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_verification_operations.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/crl_metadata_wire_layout.hpp"
#include "score/crypto/src/daemon/cert_management/slot/cert_slot_manager.hpp"
#include "score/crypto/src/daemon/cert_management/slot/slot_handler_factory.hpp"
#include "score/crypto/src/daemon/cert_management/truststore/trust_store_manager.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/common/context/context_creation_request.hpp"
#include "score/crypto/src/daemon/common/storage/kv/kv_deployment_writer.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/data_manager/data_manager.hpp"
#include "score/crypto/src/daemon/provider/cert_management/i_cert_path_validator.hpp"
#include "score/crypto/src/daemon/provider/provider_manager.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/cert_management/openssl_cert_parser.hpp"
#include "score/tests/utility/test_utility.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

namespace cert = score::crypto::daemon::cert_management;
namespace common = score::crypto::daemon::common;
namespace config = score::crypto::daemon::config;
namespace dm = score::crypto::daemon::data_manager;
namespace openssl_ns = score::crypto::daemon::provider::score_provider::openssl;
namespace path_provider = score::crypto::daemon::provider::cert_management;
namespace provider = score::crypto::daemon::provider;
namespace storage = score::crypto::daemon::common::storage;
namespace ops = score::crypto::daemon::cert_management::operations;
using Error = common::DaemonErrorCode;
using FormatType = score::crypto::FormatType;

/// Client 1 carries uid 0, which the trust-store and slot access policies below allow.
constexpr dm::ClientId kClient{1U};
constexpr std::string_view kStoreName{"verification-store"};
constexpr std::string_view kSlotName{"verification-anchor"};
constexpr std::string_view kRootVector{"score/tests/test_vectors/certificate/basic/certificate.pem"};
constexpr std::string_view kLeafVector{"score/tests/test_vectors/certificate/basic/certificate_leaf.pem"};
constexpr std::string_view kUpdatedVector{"score/tests/test_vectors/certificate/basic/certificate_updated.pem"};
constexpr std::string_view kCrlVector{"score/tests/test_vectors/certificate/basic/certificate.crl.pem"};
/// nextUpdate carried by the session CRL. It is only read back, never checked against the clock.
constexpr std::int64_t kSessionNextUpdate{2000000000};
constexpr std::int64_t kVerificationTime{1700000000};
/// An action code that no verification operation uses.
constexpr common::OperationAction kUnassignedAction{0xEEU};

std::vector<std::uint8_t> ReadFile(const std::filesystem::path& path)
{
    std::ifstream file(path, std::ios::binary);
    return std::vector<std::uint8_t>{std::istreambuf_iterator<char>(file), {}};
}

bool SameCertificate(const cert::CertObject& first, const cert::CertObject& second)
{
    const auto first_fingerprint = first.GetFingerprint();
    const auto second_fingerprint = second.GetFingerprint();
    return first_fingerprint.size() == second_fingerprint.size() &&
           std::equal(first_fingerprint.begin(), first_fingerprint.end(), second_fingerprint.begin());
}

common::OperationIdentifier VerificationOperation(common::OperationAction action)
{
    return common::OperationIdentifier{.operationActor = common::actors::OP_ACTOR_CERT_VERIFICATION,
                                       .operationAction = action};
}

/// State shared by every validator a provider creates: the requests seen and the result to return.
struct ValidationLog
{
    std::vector<path_provider::PathValidationRequest> requests;
    path_provider::PathValidationResult next;
};

/// Path validator that records every request in a shared log and returns the configured result.
class RecordingValidator final : public path_provider::ICertPathValidator
{
  public:
    explicit RecordingValidator(std::shared_ptr<ValidationLog> log) : m_log{std::move(log)} {}

    score::crypto::Expected<path_provider::PathValidationResult, Error> Validate(
        const path_provider::PathValidationRequest& request) override
    {
        m_log->requests.push_back(request);
        return m_log->next;
    }

  private:
    std::shared_ptr<ValidationLog> m_log;
};

/// Provider that supplies the OpenSSL parser and, when given one, a path validator.
class VerificationProvider final : public provider::IProvider
{
  public:
    /// @param log Log that the validators this provider creates share. Null means the provider supplies no validator.
    VerificationProvider(path_provider::ICertParser::Sptr parser, std::shared_ptr<ValidationLog> log)
        : m_parser{std::move(parser)}, m_log{std::move(log)}
    {
    }

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

    path_provider::ICertParser::Sptr GetCertParser() override
    {
        return m_parser;
    }

    std::shared_ptr<path_provider::ICertPathValidator> GetCertPathValidator() override
    {
        if (!m_log)
        {
            return nullptr;
        }
        return std::make_shared<RecordingValidator>(m_log);
    }

    [[nodiscard]] common::ProviderCapability GetProviderCapabilities() override
    {
        return common::ProviderCapability::kCertManagement;
    }

  private:
    path_provider::ICertParser::Sptr m_parser;
    std::shared_ptr<ValidationLog> m_log;
    common::ProviderId m_provider_id{common::kInvalidProviderId};
    common::ProviderName m_provider_name;
    bool m_initialized{false};
};

/// Builds a provider manager that serves the OpenSSL parser and validators recording into the given log.
std::shared_ptr<provider::ProviderManager> MakeProviderManager(
    const std::shared_ptr<openssl_ns::OpenSslCertParser>& parser,
    std::shared_ptr<ValidationLog> log)
{
    auto manager = std::make_shared<provider::ProviderManager>(config::ProviderInitConfig{});
    EXPECT_TRUE(manager->RegisterProvider("OPENSSL",
                                          std::make_shared<VerificationProvider>(parser, std::move(log)),
                                          common::CryptoProviderType::SOFTWARE));
    EXPECT_TRUE(manager->Initialize());
    return manager;
}

class CertVerificationFixture : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        ::tests::utility::ConfigureTestLogging();
        m_dir = ::tests::utility::TempDirectory("score_cert_verify_ctx");
        std::filesystem::remove_all(m_dir);
        std::filesystem::create_directories(m_dir);

        m_root_bytes = ReadFile(::tests::utility::TestVectorPath(kRootVector));
        m_leaf_bytes = ReadFile(::tests::utility::TestVectorPath(kLeafVector));
        m_updated_bytes = ReadFile(::tests::utility::TestVectorPath(kUpdatedVector));
        m_crl_bytes = ReadFile(::tests::utility::TestVectorPath(kCrlVector));
        ASSERT_FALSE(m_root_bytes.empty());
        ASSERT_FALSE(m_leaf_bytes.empty());
        ASSERT_FALSE(m_updated_bytes.empty());
        ASSERT_FALSE(m_crl_bytes.empty());

        m_parser = std::make_shared<openssl_ns::OpenSslCertParser>(common::ProviderId{0U});
        m_log = std::make_shared<ValidationLog>();
        m_validator = std::make_shared<RecordingValidator>(m_log);
        m_provider_manager = MakeProviderManager(m_parser, m_log);

        // The member slot starts empty; AddMember below writes the root certificate to its cert_path.
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

        const auto handle = m_trust_store_manager->ResolveByName(std::string{kStoreName});
        ASSERT_TRUE(handle.has_value());
        m_trust_store_handle = handle.value();

        const auto root = m_parser->ParseCertificate(m_root_bytes.data(), m_root_bytes.size(), FormatType::kPem);
        ASSERT_TRUE(root.has_value());
        ASSERT_TRUE(m_trust_store_manager->AddMember(m_trust_store_handle, root.value(), kClient).has_value());

        const auto members = m_trust_store_manager->GetMemberSlotHandles(m_trust_store_handle);
        ASSERT_TRUE(members.has_value());
        ASSERT_EQ(members.value().size(), 1U);
        m_member_slot = members.value().front();

        // The member CRL is validated against the root it revokes for, then stored with its metadata.
        cert::CrlData crl{m_crl_bytes, FormatType::kPem, std::nullopt};
        const auto crl_metadata =
            m_parser->ValidateCrl(crl, m_root_bytes.data(), m_root_bytes.size(), FormatType::kPem);
        ASSERT_TRUE(crl_metadata.has_value());
        crl.metadata = crl_metadata.value();
        ASSERT_TRUE(
            m_trust_store_manager->StoreCrlForMember(m_trust_store_handle, m_member_slot, crl, kClient).has_value());

        const auto trust_store_node = m_service->ResolveTrustStoreNode(std::string{kStoreName}, kClient);
        ASSERT_TRUE(trust_store_node.has_value());
        m_trust_store_node = trust_store_node.value();

        m_leaf_node = RegisterEphemeral(m_leaf_bytes);
        m_root_node = RegisterEphemeral(m_root_bytes);
        m_updated_node = RegisterEphemeral(m_updated_bytes);
    }

    /// Register a certificate that no slot backs, as a child of the client's trust-store node.
    dm::DataNodeId RegisterEphemeral(const std::vector<std::uint8_t>& pem)
    {
        const auto object = m_parser->ParseCertificate(pem.data(), pem.size(), FormatType::kPem);
        if (!object.has_value())
        {
            ADD_FAILURE() << "The test certificate did not parse";
            return 0U;
        }
        cert::CertRegistrationParams params;
        params.client_id = kClient;
        params.parent_id = m_trust_store_node;
        params.slot_handle = cert::CertSlotHandle{};
        const auto registered = m_service->RegisterCertificate(params, object.value());
        if (!registered.has_value())
        {
            ADD_FAILURE() << "The test certificate could not be registered";
            return 0U;
        }
        return registered.value().node_id;
    }

    /// Create a session on the fixture's collaborators.
    std::unique_ptr<cert::CertVerificationSession> MakeSession() const
    {
        cert::CertExecutionContext ctx;
        ctx.client_id = kClient;
        ctx.context_node_id = 0U;
        return std::make_unique<cert::CertVerificationSession>(
            ctx, cert::CertVerificationSession::Services{m_service, m_parser, m_validator});
    }

    std::filesystem::path m_dir;
    std::vector<std::uint8_t> m_root_bytes;
    std::vector<std::uint8_t> m_leaf_bytes;
    std::vector<std::uint8_t> m_updated_bytes;
    std::vector<std::uint8_t> m_crl_bytes;
    std::shared_ptr<openssl_ns::OpenSslCertParser> m_parser;
    std::shared_ptr<ValidationLog> m_log;
    std::shared_ptr<RecordingValidator> m_validator;
    std::shared_ptr<provider::ProviderManager> m_provider_manager;
    std::shared_ptr<cert::CertSlotRegistry> m_registry;
    std::shared_ptr<cert::CertSlotManager> m_slot_manager;
    std::shared_ptr<cert::TrustStoreManager> m_trust_store_manager;
    std::shared_ptr<dm::DataManager> m_data_manager;
    std::shared_ptr<cert::CertManagementService> m_service;
    cert::TrustStoreHandle m_trust_store_handle{};
    cert::CertSlotHandle m_member_slot{};
    dm::DataNodeId m_trust_store_node{0U};
    dm::DataNodeId m_leaf_node{0U};
    dm::DataNodeId m_root_node{0U};
    dm::DataNodeId m_updated_node{0U};
};

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

TEST(CertVerificationContextFactoryTest, RefusesCreationWhenNoPathValidatorIsAvailable)
{
    ::tests::utility::ConfigureTestLogging();
    const auto parser = std::make_shared<openssl_ns::OpenSslCertParser>(common::ProviderId{0U});
    const auto manager = MakeProviderManager(parser, nullptr);
    const auto source = std::make_shared<const cert::SlotHandlerFactory>(manager);

    cert::CertVerificationContextFactory factory{source, manager, nullptr};
    const common::ContextCreationRequest request{};
    const auto created = factory.Create(request);

    ASSERT_FALSE(created.has_value());
    EXPECT_EQ(created.error(), Error::kUnsupportedOperation);
}

TEST(CertVerificationContextFactoryTest, CreatesAHandlerWhenThePathValidatorIsAvailable)
{
    ::tests::utility::ConfigureTestLogging();
    const auto parser = std::make_shared<openssl_ns::OpenSslCertParser>(common::ProviderId{0U});
    const auto manager = MakeProviderManager(parser, std::make_shared<ValidationLog>());
    const auto source = std::make_shared<const cert::SlotHandlerFactory>(manager);

    cert::CertVerificationContextFactory factory{source, manager, nullptr};
    const common::ContextCreationRequest request{};
    const auto created = factory.Create(request);

    ASSERT_TRUE(created.has_value());
    EXPECT_NE(created.value(), nullptr);
}

// ---------------------------------------------------------------------------
// Executor
// ---------------------------------------------------------------------------

class CertVerificationExecutorTest : public CertVerificationFixture
{
};

TEST_F(CertVerificationExecutorTest, RefusesAnUnknownOperationAndAnotherActor)
{
    auto session = MakeSession();
    const cert::CertVerificationExecutor executor{};
    common::RequestParameters request{};

    const auto unknown = executor.Execute(*session, VerificationOperation(kUnassignedAction), request);
    ASSERT_FALSE(unknown.has_value());
    EXPECT_EQ(unknown.error(), Error::kUnsupportedOperation);

    const common::OperationIdentifier wrong_actor{.operationActor = common::actors::OP_ACTOR_CERT_MANAGEMENT,
                                                  .operationAction = ops::CERT_VERIFY};
    const auto refused = executor.Execute(*session, wrong_actor, request);
    ASSERT_FALSE(refused.has_value());
    EXPECT_EQ(refused.error(), Error::kUnsupportedOperation);
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

class CertVerificationSessionTest : public CertVerificationFixture
{
};

TEST_F(CertVerificationSessionTest, BuildsTheRequestAndPassesVerdictsThrough)
{
    // Leaf, presented chain, additional certificates, explicit anchor, trust store, CRLs, and policies.
    auto session = MakeSession();
    ASSERT_TRUE(session->SetChain({m_leaf_node, m_updated_node}).has_value());
    ASSERT_TRUE(session->SetUntrusted({m_leaf_node, m_root_node}).has_value());
    ASSERT_TRUE(session->SetTrusted({m_root_node}).has_value());
    ASSERT_TRUE(session->SetTrustStore(m_trust_store_node).has_value());

    const auto leaf_entry = m_service->ResolveCertEntry(kClient, m_leaf_node);
    ASSERT_TRUE(leaf_entry.has_value());
    score::crypto::CrlMetadata session_metadata{};
    session_metadata.next_update = kSessionNextUpdate;
    leaf_entry.value()->AttachSessionCrl(cert::CrlData{{0x30U, 0x03U, 0x02U}, FormatType::kDer, session_metadata});

    session->SetChainTerminationPolicy(score::crypto::ChainTerminationPolicy::kTrustStoreTerminated);
    session->SetRevocationCheckPolicy(score::crypto::RevocationCheckPolicy::kCrlOnly);
    session->SetRevocationCoveragePolicy(score::crypto::RevocationCoveragePolicy::kBestEffort);
    session->SetVerificationTime(kVerificationTime);
    session->SetEvidenceMode(score::crypto::VerificationEvidenceMode::kChainAndCrl);

    const auto leaf_object = m_service->ResolveCertObject(kClient, m_leaf_node);
    const auto root_object = m_service->ResolveCertObject(kClient, m_root_node);
    const auto updated_object = m_service->ResolveCertObject(kClient, m_updated_node);
    ASSERT_TRUE(leaf_object.has_value());
    ASSERT_TRUE(root_object.has_value());
    ASSERT_TRUE(updated_object.has_value());

    score::crypto::CrlMetadata selected{};
    selected.next_update = kSessionNextUpdate;
    selected.crl_number = 7U;
    selected.fingerprint[0] = 0xABU;

    // kValid: the chain is kept and exported.
    path_provider::PathValidationResult valid;
    valid.result = score::crypto::CertVerifyResult::kValid;
    valid.chain = {leaf_object.value(), root_object.value()};
    valid.selected_crl_metadata = {selected};
    m_log->next = valid;

    const auto verdict = session->Verify();
    ASSERT_TRUE(verdict.has_value());
    EXPECT_EQ(verdict.value(), score::crypto::CertVerifyResult::kValid);
    EXPECT_EQ(session->GetVerifiedChainCertificateCount(), 2U);

    ASSERT_EQ(m_log->requests.size(), 1U);
    const auto& request = m_log->requests.front();
    ASSERT_NE(request.leaf, nullptr);
    EXPECT_TRUE(SameCertificate(*request.leaf, *leaf_object.value()));

    // The chain entry is an anchor, so it is not repeated as untrusted; the leaf is never untrusted.
    ASSERT_EQ(request.untrusted.size(), 1U);
    EXPECT_TRUE(SameCertificate(*request.untrusted.front(), *updated_object.value()));

    // The explicit anchor and the store member are the same certificate, so the anchor appears once.
    ASSERT_EQ(request.trust_anchors.size(), 1U);
    EXPECT_TRUE(SameCertificate(*request.trust_anchors.front(), *root_object.value()));

    // The leaf's session CRL and the member CRL of the store, in that order; nodes without a CRL add nothing.
    ASSERT_EQ(request.crls.size(), 2U);
    ASSERT_NE(request.crls[0], nullptr);
    ASSERT_TRUE(request.crls[0]->metadata.has_value());
    EXPECT_EQ(request.crls[0]->metadata->next_update, kSessionNextUpdate);
    ASSERT_NE(request.crls[1], nullptr);
    EXPECT_EQ(request.crls[1]->format, FormatType::kPem);

    EXPECT_EQ(request.chain_termination, score::crypto::ChainTerminationPolicy::kTrustStoreTerminated);
    EXPECT_EQ(request.revocation_check, score::crypto::RevocationCheckPolicy::kCrlOnly);
    EXPECT_EQ(request.revocation_coverage, score::crypto::RevocationCoveragePolicy::kBestEffort);
    ASSERT_TRUE(request.verification_time_epoch_s.has_value());
    EXPECT_EQ(request.verification_time_epoch_s.value(), kVerificationTime);

    const auto exported = session->ExportVerifiedCertificate(0U, FormatType::kDer);
    const auto expected = m_parser->EncodeCertificate(*leaf_object.value(), FormatType::kDer);
    ASSERT_TRUE(exported.has_value());
    ASSERT_TRUE(expected.has_value());
    EXPECT_EQ(exported.value(), expected.value());

    // kRevoked: no chain is kept, and the selected CRL metadata is still reported.
    path_provider::PathValidationResult revoked;
    revoked.result = score::crypto::CertVerifyResult::kRevoked;
    revoked.selected_crl_metadata = {selected};
    m_log->next = revoked;

    const auto revoked_verdict = session->Verify();
    ASSERT_TRUE(revoked_verdict.has_value());
    EXPECT_EQ(revoked_verdict.value(), score::crypto::CertVerifyResult::kRevoked);
    EXPECT_EQ(session->GetVerifiedChainCertificateCount(), 0U);
    EXPECT_FALSE(session->ExportVerifiedChain(FormatType::kPem).has_value());

    const auto packed = session->GetSelectedCrlMetadata();
    ASSERT_TRUE(packed.has_value());
    ASSERT_EQ(packed.value().size(), cert::CrlMetadataWireLayout::kEntrySize);
    EXPECT_EQ(packed.value().front(), 0xABU);
}

TEST_F(CertVerificationSessionTest, ResetClearsTheInputsAndReleasesTheTrustStore)
{
    auto session = MakeSession();
    ASSERT_TRUE(session->SetLeaf(m_leaf_node).has_value());
    ASSERT_TRUE(session->SetTrustStore(m_trust_store_node).has_value());

    session->Reset();

    // The leaf is gone, so the request cannot be built.
    const auto verdict = session->Verify();
    ASSERT_FALSE(verdict.has_value());
    EXPECT_EQ(verdict.error(), Error::kInvalidArgument);
    EXPECT_TRUE(m_log->requests.empty());
}

// ---------------------------------------------------------------------------
// Context handler
// ---------------------------------------------------------------------------

class CertVerificationContextHandlerTest : public CertVerificationFixture
{
};

TEST_F(CertVerificationContextHandlerTest, InitializesOnceAndResetKeepsTheIdentity)
{
    const auto handler = std::make_shared<cert::CertVerificationContextHandler>(
        std::make_shared<const cert::CertVerificationExecutor>(),
        cert::CertVerificationSession::Services{m_service, m_parser, m_validator});

    common::RequestParameters leaf_request{std::uint64_t{m_leaf_node}};
    const auto before_init = handler->Execute(VerificationOperation(ops::CERT_VERIFY_SET_LEAF), leaf_request);
    ASSERT_FALSE(before_init.has_value());
    EXPECT_EQ(before_init.error(), Error::kInvalidOperation);

    common::InitializationParams init;
    init.client_id = kClient;
    init.context_node_id = 0U;
    init.provider_id = common::kInvalidProviderId;
    ASSERT_TRUE(handler->InitializeContext(init).has_value());
    const auto second_init = handler->InitializeContext(init);
    ASSERT_FALSE(second_init.has_value());
    EXPECT_EQ(second_init.error(), Error::kInvalidOperation);

    // An unknown trust-store node is refused, and the handler keeps working.
    ASSERT_TRUE(handler->Execute(VerificationOperation(ops::CERT_VERIFY_SET_LEAF), leaf_request).has_value());
    common::RequestParameters unknown_store{std::uint64_t{999999U}};
    EXPECT_FALSE(handler->Execute(VerificationOperation(ops::CERT_VERIFY_SET_TRUST_STORE), unknown_store).has_value());
    common::RequestParameters store_request{std::uint64_t{m_trust_store_node}};
    EXPECT_TRUE(handler->Execute(VerificationOperation(ops::CERT_VERIFY_SET_TRUST_STORE), store_request).has_value());

    // Reset clears the leaf and the trust-store binding. The context stays initialized, so verification reports the
    // missing leaf rather than an uninitialized context.
    EXPECT_TRUE(handler->Reset().has_value());
    common::RequestParameters empty{};
    const auto verify = handler->Execute(VerificationOperation(ops::CERT_VERIFY), empty);
    ASSERT_FALSE(verify.has_value());
    EXPECT_EQ(verify.error(), Error::kInvalidArgument);
}

}  // namespace

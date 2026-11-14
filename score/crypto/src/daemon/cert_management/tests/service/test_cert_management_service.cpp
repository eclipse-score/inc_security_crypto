/*******************************************************************************
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
 *******************************************************************************/
//
// Component-level tests for CertManagementService.
//
// Uses a real DataManager, CertSlotRegistry, TrustStoreManager, SlotHandlerFactory,
// OpenSslCertParser, and FileBackedSlotHandler backed by the central test vector
// at score/tests/test_vectors/certificate/basic/certificate.pem.
//
// All cert bytes come from the central test-vector directory so that these
// tests share the same known-answer inputs as the integration and provider
// parser tests.
//
// Test subjects:
//   - Slot resolution and cert load via the executor call sequence
//     (ResolveCertSlotNode → ResolveCertSlotHandle → Load)
//   - ResolveCertObject round-trip
//   - Cert node release and subsequent unresolvability
//   - Load creates independent CertEntries per client; shared CertObject bytes
//     avoid repeated disk reads (certificate cache in CertSlotManager)
//   - Mediator-style client cleanup isolates clients — purging one leaves the other intact
//   - UpdateSlot/ClearSlot propagate through the TrustStoreManager anchor cache

#include "score/crypto/src/daemon/cert_management/core/cert_entry.hpp"
#include "score/crypto/src/daemon/cert_management/core/cert_management_service.hpp"
#include "score/crypto/src/daemon/cert_management/slot/cert_slot_manager.hpp"
#include "score/crypto/src/daemon/cert_management/slot/slot_handler_factory.hpp"
#include "score/crypto/src/daemon/cert_management/truststore/trust_store_manager.hpp"
#include "score/crypto/src/daemon/common/storage/kv/kv_deployment_writer.hpp"
#include "score/crypto/src/daemon/data_manager/data_manager.hpp"
#include "score/crypto/src/daemon/provider/cert_management/i_cert_parser.hpp"
#include "score/crypto/src/daemon/provider/provider_manager.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/cert_management/openssl_cert_parser.hpp"
#include "score/tests/utility/test_utility.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace
{
namespace cert = score::crypto::daemon::cert_management;
namespace dm = score::crypto::daemon::data_manager;
namespace config = score::crypto::daemon::config;
namespace provider = score::crypto::daemon::provider;
namespace common = score::crypto::daemon::common;
namespace openssl_ns = score::crypto::daemon::provider::score_provider::openssl;
namespace storage = score::crypto::daemon::common::storage;

class TestParserProvider final : public provider::IProvider
{
  public:
    explicit TestParserProvider(std::shared_ptr<openssl_ns::OpenSslCertParser> parser) : m_parser{std::move(parser)} {}

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
    std::shared_ptr<openssl_ns::OpenSslCertParser> m_parser;
    common::ProviderId m_provider_id{common::kInvalidProviderId};
    common::ProviderName m_provider_name;
    bool m_initialized{false};
};

// client_id layout: upper 32 bits = UID, lower 32 bits = PID.
// Using UID=0 to match RegisterAppResource(uid=0, ...) calls below.
static constexpr dm::ClientId kClientA = 1ULL;  // pid=1, uid=0
static constexpr dm::ClientId kClientB = 2ULL;  // pid=2, uid=0

static constexpr std::string_view kSlotName = "test/root-ca";
static constexpr std::string_view kAppResource = "root_ca";
static constexpr std::string_view kSubjectInitial = "CN=cert-management-test,O=Eclipse";
static constexpr std::string_view kSubjectUpdated = "CN=cert-management-updated,O=Eclipse";

// Common fixture: wires up a single file-backed cert slot and the service.
class CertManagementServiceTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        ::tests::utility::ConfigureTestLogging();
        m_dir = ::tests::utility::TempDirectory("score_cert_mgmt_service");
        std::filesystem::remove_all(m_dir);
        std::filesystem::create_directories(m_dir);
        m_cert_path = m_dir / "root_ca.pem";
        m_cert_updated_path = m_dir / "root_ca_updated.pem";
        m_descriptor_path = m_dir / "root_ca.kv";

        ASSERT_TRUE(std::filesystem::copy_file(
            ::tests::utility::TestVectorPath("score/tests/test_vectors/certificate/basic/certificate.pem"),
            m_cert_path,
            std::filesystem::copy_options::overwrite_existing));
        ASSERT_TRUE(std::filesystem::copy_file(
            ::tests::utility::TestVectorPath("score/tests/test_vectors/certificate/basic/certificate_updated.pem"),
            m_cert_updated_path,
            std::filesystem::copy_options::overwrite_existing));

        // Write the KV descriptor pointing at the initial cert.
        storage::DeploymentDescriptor desc;
        desc.Set("certificate", "cert_path", m_cert_path.string());
        desc.Set("certificate", "cert_format", "pem");
        ASSERT_TRUE(storage::KvDeploymentWriter{}.Write(m_descriptor_path.string(), desc).has_value());

        m_parser = std::make_shared<openssl_ns::OpenSslCertParser>(common::ProviderId{0U});
        m_provider_manager = std::make_shared<provider::ProviderManager>(config::ProviderRoutingPolicy{});
        auto parser_provider = std::make_shared<TestParserProvider>(m_parser);
        ASSERT_TRUE(
            m_provider_manager->RegisterProvider("OPENSSL", parser_provider, common::CryptoProviderType::SOFTWARE));
        ASSERT_TRUE(m_provider_manager->Initialize());

        m_registry = std::make_shared<cert::CertSlotRegistry>();
        cert::CertSlotConfig slot_cfg;
        slot_cfg.slot_name = std::string{kSlotName};
        slot_cfg.storage_backend = "DEFAULT";
        slot_cfg.deployment_path = m_descriptor_path.string();
        slot_cfg.deployment_format = "kv";
        // uid=0 matches kClientA/kClientB (see ClientId layout note above) so tests
        // below can exercise slot-CRL write paths (UpdateSlot) as well as reads.
        slot_cfg.access_policy.allowed_write_uids = {0U};
        m_slot_handle = m_registry->RegisterSlot(slot_cfg);
        // Map uid=0 app resource "root_ca" → slot "test/root-ca"
        m_registry->RegisterAppResource(0U, std::string{kAppResource}, std::string{kSlotName});

        m_trust_store_manager = std::make_shared<cert::TrustStoreManager>();
        m_data_manager = std::make_shared<dm::DataManager>();

        auto factory = std::make_shared<cert::SlotHandlerFactory>(m_provider_manager);
        m_slot_manager = std::make_shared<cert::CertSlotManager>(m_registry, std::move(factory));
        m_service = std::make_shared<cert::CertManagementService>(
            m_data_manager, m_registry, m_trust_store_manager, m_slot_manager);
    }

    void TearDown() override
    {
        static_cast<void>(m_data_manager->deleteClientNodes(kClientA));
        static_cast<void>(m_data_manager->deleteClientNodes(kClientB));
        std::error_code ec;
        std::filesystem::remove_all(m_dir, ec);
    }

    // Mirror the executor call sequence: resolve the slot node, then load the cert.
    cert::RegisteredCert LoadCert(dm::ClientId client_id)
    {
        auto slot_res = m_service->ResolveCertSlotNode(std::string{kAppResource}, client_id);
        if (!slot_res.has_value())
            return {};
        const auto slot_node_id = slot_res.value();

        auto resolved = m_service->ResolveCertSlotHandle(client_id, slot_node_id);
        if (!resolved.has_value())
            return {};

        cert::CertRegistrationParams params;
        params.client_id = client_id;
        params.parent_id = slot_node_id;
        params.slot_handle = resolved.value();

        auto result = m_service->LoadCertificate(params);
        if (!result.has_value())
            return {};
        return result.value();
    }

    std::filesystem::path m_dir;
    std::filesystem::path m_cert_path;
    std::filesystem::path m_cert_updated_path;
    std::filesystem::path m_descriptor_path;
    cert::CertSlotHandle m_slot_handle;

    provider::ProviderManager::Sptr m_provider_manager;
    std::shared_ptr<openssl_ns::OpenSslCertParser> m_parser;
    cert::CertSlotRegistry::Sptr m_registry;
    cert::CertSlotManager::Sptr m_slot_manager;
    cert::TrustStoreManager::Sptr m_trust_store_manager;
    std::shared_ptr<dm::DataManager> m_data_manager;
    cert::CertManagementService::Sptr m_service;
};

// ---------------------------------------------------------------------------
// Basic load and metadata
// ---------------------------------------------------------------------------

TEST_F(CertManagementServiceTest, LoadCertFromSlot_ReturnsObjectWithExpectedSubject)
{
    const auto result = LoadCert(kClientA);

    ASSERT_NE(result.node_id, 0U);
    ASSERT_NE(result.instance, nullptr);
    EXPECT_EQ(result.instance->GetCertObject()->GetSubject(), kSubjectInitial);
    EXPECT_TRUE(result.instance->GetCertObject()->IsCA());
    EXPECT_EQ(result.instance->GetCertObject()->GetFingerprint().size(), score::crypto::kSha256FingerprintSize);
    EXPECT_EQ(result.instance->GetCertObject()->GetSkid().size(), 20U);
}

TEST_F(CertManagementServiceTest, CertDataNodeCanBeDestroyedAfterServiceDestruction)
{
    const auto result = LoadCert(kClientA);
    ASSERT_NE(result.node_id, 0U);

    m_service.reset();

    ASSERT_TRUE(m_data_manager->deleteClientNodes(kClientA).has_value());
}

TEST_F(CertManagementServiceTest, ResolveCertObject_ReturnsSameObjectAsLoaded)
{
    const auto result = LoadCert(kClientA);
    ASSERT_NE(result.node_id, 0U);

    const auto resolved = m_service->ResolveCertObject(kClientA, result.node_id);
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ((*resolved)->GetSubject(), kSubjectInitial);
}

// ---------------------------------------------------------------------------
// Node release
// ---------------------------------------------------------------------------

TEST_F(CertManagementServiceTest, ReleaseCertificate_NodeBecomesUnresolvable)
{
    const auto result = LoadCert(kClientA);
    ASSERT_NE(result.node_id, 0U);

    ASSERT_TRUE(m_service->ReleaseCertificate(kClientA, result.node_id).has_value());

    EXPECT_FALSE(m_service->ResolveCertObject(kClientA, result.node_id).has_value());
}

TEST_F(CertManagementServiceTest, ReleaseCertificate_UnknownNodeId_ReturnsError)
{
    EXPECT_FALSE(m_service->ReleaseCertificate(kClientA, 999U).has_value());
}

// ---------------------------------------------------------------------------
// Per-client CertEntry isolation — each Load call produces an independent
// CertEntry so that session CRL state cannot bleed across clients.
// The underlying CertObject bytes are shared via the certificate cache in
// CertSlotManager, avoiding repeated disk reads.
// ---------------------------------------------------------------------------

TEST_F(CertManagementServiceTest, LoadCertificate_SecondCallProducesIndependentCertEntry)
{
    const auto result1 = LoadCert(kClientA);
    ASSERT_NE(result1.node_id, 0U);
    ASSERT_NE(result1.instance, nullptr);

    const auto result2 = LoadCert(kClientA);
    ASSERT_NE(result2.node_id, 0U);
    ASSERT_NE(result2.instance, nullptr);

    // Independent CertEntry objects — session CRL on one cannot affect the other.
    EXPECT_NE(result1.node_id, result2.node_id);
    EXPECT_NE(result1.instance.get(), result2.instance.get());
    // But the underlying CertObject bytes are the same shared object (cache hit).
    EXPECT_EQ(result1.instance->GetCertObject().get(), result2.instance->GetCertObject().get());
}

// ---------------------------------------------------------------------------
// Slot-node deduplication
// ---------------------------------------------------------------------------

TEST_F(CertManagementServiceTest, ResolveCertSlot_SameClientAndResource_ReturnsSameNodeId)
{
    const auto id1 = m_service->ResolveCertSlotNode(std::string{kAppResource}, kClientA);
    const auto id2 = m_service->ResolveCertSlotNode(std::string{kAppResource}, kClientA);

    ASSERT_TRUE(id1.has_value());
    ASSERT_TRUE(id2.has_value());
    EXPECT_EQ(id1.value(), id2.value());
}

TEST_F(CertManagementServiceTest, ResolveCertSlot_ConcurrentCallsReuseNodePerClient)
{
    constexpr std::size_t kCallerCount = 16U;
    std::atomic<bool> start{false};
    std::vector<dm::ClientId> clients(kCallerCount);
    std::vector<dm::DataNodeId> node_ids(kCallerCount);
    std::vector<std::uint8_t> succeeded(kCallerCount, 0U);
    std::vector<std::thread> callers;
    callers.reserve(kCallerCount);

    for (std::size_t index = 0U; index < kCallerCount; ++index)
    {
        clients[index] = (index % 2U == 0U) ? kClientA : kClientB;
        callers.emplace_back([this, &start, &clients, &node_ids, &succeeded, index]() {
            while (!start.load(std::memory_order_acquire))
                std::this_thread::yield();
            const auto result = m_service->ResolveCertSlotNode(std::string{kAppResource}, clients[index]);
            if (result.has_value())
            {
                node_ids[index] = result.value();
                succeeded[index] = 1U;
            }
        });
    }

    start.store(true, std::memory_order_release);
    for (auto& caller : callers)
        caller.join();

    for (std::size_t index = 0U; index < kCallerCount; ++index)
    {
        ASSERT_EQ(succeeded[index], 1U);
        for (std::size_t previous = 0U; previous < index; ++previous)
        {
            if (clients[previous] == clients[index])
                EXPECT_EQ(node_ids[index], node_ids[previous]);
        }
    }
}

TEST_F(CertManagementServiceTest, ResolveCertSlot_ByHandleSharesResourceNodeId)
{
    const auto by_resource = m_service->ResolveCertSlotNode(std::string{kAppResource}, kClientA);
    const auto by_handle = m_service->ResolveCertSlotNode(m_slot_handle, kClientA);

    ASSERT_TRUE(by_resource.has_value());
    ASSERT_TRUE(by_handle.has_value());
    EXPECT_EQ(by_resource.value(), by_handle.value());
}

TEST_F(CertManagementServiceTest, ResolveCertSlot_UnknownResource_ReturnsError)
{
    EXPECT_FALSE(m_service->ResolveCertSlotNode("no_such_resource", kClientA).has_value());
}

// ---------------------------------------------------------------------------
// Client isolation
// ---------------------------------------------------------------------------

TEST_F(CertManagementServiceTest, MediatorCleanupThenServiceCleanup_IsolatesClients)
{
    const auto result_a = LoadCert(kClientA);
    const auto result_b = LoadCert(kClientB);
    ASSERT_NE(result_a.node_id, 0U);
    ASSERT_NE(result_b.node_id, 0U);

    ASSERT_TRUE(m_data_manager->deleteClientNodes(kClientA).has_value());
    m_service->CleanupClient(kClientA);

    // Client A's node must be gone.
    EXPECT_FALSE(m_service->ResolveCertObject(kClientA, result_a.node_id).has_value());
    // Client B must be unaffected.
    EXPECT_TRUE(m_service->ResolveCertObject(kClientB, result_b.node_id).has_value());
}

// ---------------------------------------------------------------------------
// Trust-store propagation
// ---------------------------------------------------------------------------

// CertManagementService::UpdateSlot/ClearSlot notify referencing trust
// stores internally; the notification is not a separate step for callers.
// These tests exercise the actual slot write path (CertSlotManager ->
// ICertSlotHandler).

TEST_F(CertManagementServiceTest, UpdateSlot_Certificate_NotifiesTrustStoreAnchorCache)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_mgmt__trust_stores");
    RecordProperty("Description",
                   "Propagates a certificate-slot update and refreshes the affected trust-store anchor.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "test-roots";
    ts_cfg.members.push_back(
        cert::TrustStoreMemberConfig{std::string{kSlotName}, cert::TrustStoreMemberKind::kSharedStatic});

    ASSERT_TRUE(m_trust_store_manager->Load({ts_cfg}, m_registry, m_slot_manager).has_value());

    const auto ts_handle = m_trust_store_manager->ResolveByName("test-roots").value();
    auto store = m_trust_store_manager->GetStore(ts_handle);
    ASSERT_NE(store, nullptr);
    // Bind the store so that its cache is warm and the notification refreshes it.
    ASSERT_TRUE(m_trust_store_manager->AddRef(ts_handle, kClientA).has_value());

    auto initial = store->GetAnchors();
    ASSERT_TRUE(initial.has_value());
    ASSERT_EQ(initial->size(), 1U);
    EXPECT_EQ((*initial)[0]->GetSubject(), kSubjectInitial);

    // Parse the updated cert and store it via the service.
    std::ifstream file(m_cert_updated_path, std::ios::binary);
    ASSERT_TRUE(file.is_open());
    const std::vector<std::uint8_t> updated_bytes{std::istreambuf_iterator<char>(file), {}};
    auto parsed_updated =
        m_parser->ParseCertificate(updated_bytes.data(), updated_bytes.size(), score::crypto::FormatType::kPem);
    ASSERT_TRUE(parsed_updated.has_value());

    ASSERT_TRUE(m_service->UpdateSlot(m_slot_handle, kClientA, **parsed_updated).has_value());

    auto updated = store->GetAnchors();
    ASSERT_TRUE(updated.has_value());
    ASSERT_EQ(updated->size(), 1U);
    EXPECT_EQ((*updated)[0]->GetSubject(), kSubjectUpdated);
    // Fingerprints must differ — different certs.
    EXPECT_FALSE(std::equal((*initial)[0]->GetFingerprint().begin(),
                            (*initial)[0]->GetFingerprint().end(),
                            (*updated)[0]->GetFingerprint().begin(),
                            (*updated)[0]->GetFingerprint().end()));
}

// A write refused by the access check never reaches the backend, so the service must not notify
// trust stores. A warm store keeps its anchors because no reload is triggered.
TEST_F(CertManagementServiceTest, DeniedUpdateSlot_Certificate_DoesNotReloadWarmTrustStore)
{
    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "test-roots";
    ts_cfg.members.push_back(
        cert::TrustStoreMemberConfig{std::string{kSlotName}, cert::TrustStoreMemberKind::kSharedStatic});

    ASSERT_TRUE(m_trust_store_manager->Load({ts_cfg}, m_registry, m_slot_manager).has_value());

    const auto ts_handle = m_trust_store_manager->ResolveByName("test-roots").value();
    auto store = m_trust_store_manager->GetStore(ts_handle);
    ASSERT_NE(store, nullptr);
    ASSERT_TRUE(m_trust_store_manager->AddRef(ts_handle, kClientA).has_value());

    auto initial = store->GetAnchors();
    ASSERT_TRUE(initial.has_value());
    ASSERT_EQ(initial->size(), 1U);
    EXPECT_EQ((*initial)[0]->GetSubject(), kSubjectInitial);

    // Replace the on-disk certificate out of band. Only a reload of the store would observe it.
    std::filesystem::copy_file(m_cert_updated_path, m_cert_path, std::filesystem::copy_options::overwrite_existing);

    std::ifstream file(m_cert_updated_path, std::ios::binary);
    ASSERT_TRUE(file.is_open());
    const std::vector<std::uint8_t> updated_bytes{std::istreambuf_iterator<char>(file), {}};
    auto parsed_updated =
        m_parser->ParseCertificate(updated_bytes.data(), updated_bytes.size(), score::crypto::FormatType::kPem);
    ASSERT_TRUE(parsed_updated.has_value());

    // UID 99 is not in allowed_write_uids ({0}), so the access check refuses the write before the backend.
    constexpr dm::ClientId kDeniedClient = (99ULL << 32) | 3ULL;
    EXPECT_FALSE(m_service->UpdateSlot(m_slot_handle, kDeniedClient, **parsed_updated).has_value());

    auto after = store->GetAnchors();
    ASSERT_TRUE(after.has_value());
    ASSERT_EQ(after->size(), 1U);
    EXPECT_EQ((*after)[0]->GetSubject(), kSubjectInitial);
}

TEST_F(CertManagementServiceTest, ClearSlot_NotifiesTrustStoreAnchorCache)
{
    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "test-roots";
    ts_cfg.members.push_back(
        cert::TrustStoreMemberConfig{std::string{kSlotName}, cert::TrustStoreMemberKind::kSharedStatic});

    ASSERT_TRUE(m_trust_store_manager->Load({ts_cfg}, m_registry, m_slot_manager).has_value());

    const auto ts_handle = m_trust_store_manager->ResolveByName("test-roots").value();
    auto store = m_trust_store_manager->GetStore(ts_handle);
    ASSERT_NE(store, nullptr);
    // Bind the store so that its cache is warm and the notification refreshes it.
    ASSERT_TRUE(m_trust_store_manager->AddRef(ts_handle, kClientA).has_value());

    auto initial = store->GetAnchors();
    ASSERT_TRUE(initial.has_value());
    ASSERT_EQ(initial->size(), 1U);

    // Clear via the service — no manual notify call.
    ASSERT_TRUE(m_service->ClearSlot(m_slot_handle, kClientA).has_value());

    auto updated = store->GetAnchors();
    ASSERT_TRUE(updated.has_value());
    EXPECT_TRUE(updated->empty());
}

// ---------------------------------------------------------------------------
// Ephemeral cert registration — RegisterCertificate with an invalid slot
// handle (no persistent backing). The caller supplies a pre-parsed CertObject;
// the service creates a CertDataNode under the given parent and registers the
// entry in the ephemeral (non-slot-keyed) section of the cert registry.
// ---------------------------------------------------------------------------

TEST_F(CertManagementServiceTest, RegisterCertificate_EphemeralPath_CreatesResolvableNode)
{
    // Read cert bytes from the test-vector file (already copied to m_cert_path in SetUp).
    std::ifstream file(m_cert_path, std::ios::binary);
    ASSERT_TRUE(file.is_open());
    const std::vector<std::uint8_t> bytes{std::istreambuf_iterator<char>(file), {}};
    ASSERT_FALSE(bytes.empty());

    auto parsed = m_parser->ParseCertificate(bytes.data(), bytes.size(), score::crypto::FormatType::kPem);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ((*parsed)->GetSubject(), kSubjectInitial);

    // Use the slot node as the parent (mirrors the executor call sequence).
    const auto slot_node_id = m_service->ResolveCertSlotNode(std::string{kAppResource}, kClientA);
    ASSERT_TRUE(slot_node_id.has_value());

    // Pass an invalid CertSlotHandle to register as ephemeral (no slot backing).
    cert::CertRegistrationParams params;
    params.client_id = kClientA;
    params.parent_id = slot_node_id.value();
    params.slot_handle = cert::CertSlotHandle{};

    const auto result = m_service->RegisterCertificate(params, *parsed);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->node_id, 0U);
    ASSERT_NE(result->instance, nullptr);
    EXPECT_EQ(result->instance->GetCertObject()->GetSubject(), kSubjectInitial);

    // The node must be resolvable immediately after registration.
    const auto resolved = m_service->ResolveCertObject(kClientA, result->node_id);
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ((*resolved)->GetSubject(), kSubjectInitial);

    // Releasing the ephemeral node must make it unresolvable.
    ASSERT_TRUE(m_service->ReleaseCertificate(kClientA, result->node_id).has_value());
    EXPECT_FALSE(m_service->ResolveCertObject(kClientA, result->node_id).has_value());
}

// ---------------------------------------------------------------------------
// ResolveCertEntry — session CRL attachment path.
//
// AttachSessionCrl() was removed from CertManagementService; the executor now
// calls ResolveCertEntry() directly and calls instance->AttachSessionCrl().
// These tests verify the entry-level behaviour accessible via the service.
// ---------------------------------------------------------------------------

TEST_F(CertManagementServiceTest, SessionCrl_StoresInMemoryNotOnDisk)
{
    const auto result = LoadCert(kClientA);
    ASSERT_NE(result.node_id, 0U);
    EXPECT_FALSE(result.instance->HasSessionCrl());
    EXPECT_EQ(result.instance->GetSessionCrlSnapshot(), nullptr);

    const std::vector<std::uint8_t> crl_bytes{0xC0U, 0xC1U, 0xC2U};
    auto instance_res = m_service->ResolveCertEntry(kClientA, result.node_id);
    ASSERT_TRUE(instance_res.has_value());
    instance_res.value()->AttachSessionCrl(cert::CrlData{crl_bytes, score::crypto::FormatType::kDer});

    EXPECT_TRUE(result.instance->HasSessionCrl());
    const auto session_crl_snapshot = result.instance->GetSessionCrlSnapshot();
    ASSERT_NE(session_crl_snapshot, nullptr);
    EXPECT_EQ(session_crl_snapshot->bytes, crl_bytes);
    EXPECT_EQ(session_crl_snapshot->format, score::crypto::FormatType::kDer);

    result.instance->ClearSessionCrl();
    EXPECT_FALSE(result.instance->HasSessionCrl());
    EXPECT_EQ(result.instance->GetSessionCrlSnapshot(), nullptr);

    EXPECT_FALSE(std::filesystem::exists(m_dir / "root_ca.crl"));
}

// A session CRL snapshot is immutable: re-attaching or clearing the CRL yields a new state for
// later readers and leaves a snapshot already handed out unchanged.
TEST_F(CertManagementServiceTest, SessionCrl_SnapshotUnaffectedByReattachAndClear)
{
    const auto result = LoadCert(kClientA);
    ASSERT_NE(result.node_id, 0U);

    const std::vector<std::uint8_t> first_bytes{0x01U, 0x02U};
    result.instance->AttachSessionCrl(cert::CrlData{first_bytes, score::crypto::FormatType::kDer});
    const auto first = result.instance->GetSessionCrlSnapshot();
    ASSERT_NE(first, nullptr);
    EXPECT_EQ(result.instance->GetSessionCrlSnapshot().get(), first.get());

    const std::vector<std::uint8_t> second_bytes{0x03U};
    result.instance->AttachSessionCrl(cert::CrlData{second_bytes, score::crypto::FormatType::kPem});
    const auto second = result.instance->GetSessionCrlSnapshot();
    ASSERT_NE(second, nullptr);
    EXPECT_NE(second.get(), first.get());
    EXPECT_EQ(second->bytes, second_bytes);
    EXPECT_EQ(second->format, score::crypto::FormatType::kPem);

    result.instance->ClearSessionCrl();
    EXPECT_EQ(result.instance->GetSessionCrlSnapshot(), nullptr);
    EXPECT_EQ(first->bytes, first_bytes);
    EXPECT_EQ(first->format, score::crypto::FormatType::kDer);
    EXPECT_EQ(second->bytes, second_bytes);
}

TEST_F(CertManagementServiceTest, SessionCrl_UnknownNode_ReturnsError)
{
    EXPECT_FALSE(m_service->ResolveCertEntry(kClientA, 999U).has_value());
}

// ---------------------------------------------------------------------------
// ResolveCertObjectWithCrlMetadata
//
// This backs the certificate-object metadata query: it reports CRL metadata
// from the session association when present, and otherwise falls back to the
// slot's persisted CRL metadata when the entry was loaded from a slot.
// Ephemeral (non-slot) certs have no fallback.
// ---------------------------------------------------------------------------

score::crypto::CrlMetadata MakeCrlMetadata(std::uint8_t seed)
{
    score::crypto::CrlMetadata metadata;
    metadata.fingerprint.fill(seed);
    metadata.issuer_fingerprint.fill(static_cast<std::uint8_t>(seed + 1U));
    metadata.this_update = 1000 + seed;
    metadata.next_update = 2000 + seed;
    metadata.crl_number = 3000U + seed;
    return metadata;
}

TEST_F(CertManagementServiceTest, ResolveCertObjectWithCrlMetadata_NoCrlAnywhere_ReturnsNoMetadata)
{
    const auto result = LoadCert(kClientA);
    ASSERT_NE(result.node_id, 0U);

    const auto resolved = m_service->ResolveCertObjectWithCrlMetadata(kClientA, result.node_id);
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved->cert->GetSubject(), kSubjectInitial);
    EXPECT_FALSE(resolved->crl_metadata.has_value());
}

TEST_F(CertManagementServiceTest, ResolveCertObjectWithCrlMetadata_SlotHasPersistedCrl_FallsBackToSlotMetadata)
{
    const auto result = LoadCert(kClientA);
    ASSERT_NE(result.node_id, 0U);
    ASSERT_FALSE(result.instance->HasSessionCrl());

    const std::vector<std::uint8_t> crl_bytes{0xC0U, 0xC1U, 0xC2U};
    const auto slot_metadata = MakeCrlMetadata(0x11U);
    ASSERT_TRUE(m_service
                    ->UpdateSlot(m_slot_handle,
                                 kClientA,
                                 cert::CrlData{crl_bytes, score::crypto::FormatType::kDer, slot_metadata})
                    .has_value());

    const auto resolved = m_service->ResolveCertObjectWithCrlMetadata(kClientA, result.node_id);
    ASSERT_TRUE(resolved.has_value());
    ASSERT_TRUE(resolved->crl_metadata.has_value());
    EXPECT_EQ(resolved->crl_metadata->fingerprint, slot_metadata.fingerprint);
    EXPECT_EQ(resolved->crl_metadata->crl_number, slot_metadata.crl_number);
}

TEST_F(CertManagementServiceTest, ResolveCertObjectWithCrlMetadata_SessionCrlPresent_TakesPrecedenceOverSlotCrl)
{
    const auto result = LoadCert(kClientA);
    ASSERT_NE(result.node_id, 0U);

    // Persist a CRL on the slot itself...
    const std::vector<std::uint8_t> slot_crl_bytes{0xC0U, 0xC1U, 0xC2U};
    const auto slot_metadata = MakeCrlMetadata(0x11U);
    ASSERT_TRUE(m_service
                    ->UpdateSlot(m_slot_handle,
                                 kClientA,
                                 cert::CrlData{slot_crl_bytes, score::crypto::FormatType::kDer, slot_metadata})
                    .has_value());

    // ...but attach a *different* session-scoped CRL to this entry.
    const std::vector<std::uint8_t> session_crl_bytes{0xD0U, 0xD1U};
    const auto session_metadata = MakeCrlMetadata(0x22U);
    result.instance->AttachSessionCrl(
        cert::CrlData{session_crl_bytes, score::crypto::FormatType::kDer, session_metadata});

    const auto resolved = m_service->ResolveCertObjectWithCrlMetadata(kClientA, result.node_id);
    ASSERT_TRUE(resolved.has_value());
    ASSERT_TRUE(resolved->crl_metadata.has_value());
    // Session metadata wins — the slot's persisted CRL must not leak through.
    EXPECT_EQ(resolved->crl_metadata->fingerprint, session_metadata.fingerprint);
    EXPECT_EQ(resolved->crl_metadata->crl_number, session_metadata.crl_number);
}

TEST_F(CertManagementServiceTest, ResolveCertObjectWithCrlMetadata_EphemeralCert_NoSlotFallback_ReturnsNoMetadata)
{
    std::ifstream file(m_cert_path, std::ios::binary);
    ASSERT_TRUE(file.is_open());
    const std::vector<std::uint8_t> bytes{std::istreambuf_iterator<char>(file), {}};
    auto parsed = m_parser->ParseCertificate(bytes.data(), bytes.size(), score::crypto::FormatType::kPem);
    ASSERT_TRUE(parsed.has_value());

    const auto slot_node_id = m_service->ResolveCertSlotNode(std::string{kAppResource}, kClientA);
    ASSERT_TRUE(slot_node_id.has_value());

    cert::CertRegistrationParams params;
    params.client_id = kClientA;
    params.parent_id = slot_node_id.value();
    params.slot_handle = cert::CertSlotHandle{};  // ephemeral — no slot backing
    const auto registered = m_service->RegisterCertificate(params, *parsed);
    ASSERT_TRUE(registered.has_value());

    const auto resolved = m_service->ResolveCertObjectWithCrlMetadata(kClientA, registered->node_id);
    ASSERT_TRUE(resolved.has_value());
    EXPECT_FALSE(resolved->crl_metadata.has_value());
}

TEST_F(CertManagementServiceTest, ResolveCertObjectWithCrlMetadata_SlotNodeNotYetLoaded_ReadsCrlFromSlot)
{
    const std::vector<std::uint8_t> crl_bytes{0xC0U, 0xC1U, 0xC2U};
    const auto slot_metadata = MakeCrlMetadata(0x33U);
    ASSERT_TRUE(m_service
                    ->UpdateSlot(m_slot_handle,
                                 kClientA,
                                 cert::CrlData{crl_bytes, score::crypto::FormatType::kDer, slot_metadata})
                    .has_value());

    // Resolve the bare slot node (kCertSlot), never Load()-ed into a CertEntry.
    const auto slot_node_id = m_service->ResolveCertSlotNode(std::string{kAppResource}, kClientA);
    ASSERT_TRUE(slot_node_id.has_value());

    const auto resolved = m_service->ResolveCertObjectWithCrlMetadata(kClientA, slot_node_id.value());
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved->cert->GetSubject(), kSubjectInitial);
    ASSERT_TRUE(resolved->crl_metadata.has_value());
    EXPECT_EQ(resolved->crl_metadata->crl_number, slot_metadata.crl_number);
}

TEST_F(CertManagementServiceTest, ResolveCertObjectWithCrlMetadata_UnknownNode_ReturnsError)
{
    EXPECT_FALSE(m_service->ResolveCertObjectWithCrlMetadata(kClientA, 999U).has_value());
}

// ---------------------------------------------------------------------------
// ResolveCrlData
//
// This is the CRL propagation source resolver: it returns the CRL bytes (not
// only metadata) to copy into a destination slot or trust-store member, as used
// by the planned SaveCertificateWithCrl and AddCertificateToTrustStoreWithCrl
// operations. Same session-vs-slot precedence as
// ResolveCertObjectWithCrlMetadata.
// ---------------------------------------------------------------------------

TEST_F(CertManagementServiceTest, ResolveCrl_NoCrlAnywhere_ReturnsNulloptSuccess)
{
    const auto result = LoadCert(kClientA);
    ASSERT_NE(result.node_id, 0U);

    const auto resolved = m_service->ResolveCrlData(kClientA, result.node_id);
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved.value(), nullptr);
}

TEST_F(CertManagementServiceTest, ResolveCrl_SlotHasPersistedCrl_NoSessionCrl_ReturnsSlotCrlBytes)
{
    const auto result = LoadCert(kClientA);
    ASSERT_NE(result.node_id, 0U);

    const std::vector<std::uint8_t> crl_bytes{0xC0U, 0xC1U, 0xC2U};
    const auto slot_metadata = MakeCrlMetadata(0x11U);
    ASSERT_TRUE(m_service
                    ->UpdateSlot(m_slot_handle,
                                 kClientA,
                                 cert::CrlData{crl_bytes, score::crypto::FormatType::kDer, slot_metadata})
                    .has_value());

    const auto resolved = m_service->ResolveCrlData(kClientA, result.node_id);
    ASSERT_TRUE(resolved.has_value());
    ASSERT_NE(resolved.value(), nullptr);
    EXPECT_EQ((*resolved)->bytes, crl_bytes);
    EXPECT_EQ((*resolved)->format, score::crypto::FormatType::kDer);
    ASSERT_TRUE((*resolved)->metadata.has_value());
    EXPECT_EQ((*resolved)->metadata->crl_number, slot_metadata.crl_number);
}

TEST_F(CertManagementServiceTest, ResolveCrl_SessionCrlPresent_TakesPrecedenceOverSlotCrl)
{
    const auto result = LoadCert(kClientA);
    ASSERT_NE(result.node_id, 0U);

    // Persist a different CRL on the slot itself...
    const std::vector<std::uint8_t> slot_crl_bytes{0xC0U, 0xC1U, 0xC2U};
    ASSERT_TRUE(m_service
                    ->UpdateSlot(m_slot_handle,
                                 kClientA,
                                 cert::CrlData{slot_crl_bytes, score::crypto::FormatType::kDer, MakeCrlMetadata(0x11U)})
                    .has_value());

    // ...but attach a session-scoped CRL to this entry.
    const std::vector<std::uint8_t> session_crl_bytes{0xD0U, 0xD1U};
    const auto session_metadata = MakeCrlMetadata(0x22U);
    result.instance->AttachSessionCrl(
        cert::CrlData{session_crl_bytes, score::crypto::FormatType::kPem, session_metadata});

    const auto resolved = m_service->ResolveCrlData(kClientA, result.node_id);
    ASSERT_TRUE(resolved.has_value());
    ASSERT_NE(resolved.value(), nullptr);
    // Session CRL wins — the slot's persisted CRL must not leak through.
    EXPECT_EQ((*resolved)->bytes, session_crl_bytes);
    EXPECT_EQ((*resolved)->format, score::crypto::FormatType::kPem);
    ASSERT_TRUE((*resolved)->metadata.has_value());
    EXPECT_EQ((*resolved)->metadata->crl_number, session_metadata.crl_number);
}

TEST_F(CertManagementServiceTest, ResolveCrl_EphemeralCert_NoSessionCrl_ReturnsNulloptSuccess)
{
    std::ifstream file(m_cert_path, std::ios::binary);
    ASSERT_TRUE(file.is_open());
    const std::vector<std::uint8_t> bytes{std::istreambuf_iterator<char>(file), {}};
    auto parsed = m_parser->ParseCertificate(bytes.data(), bytes.size(), score::crypto::FormatType::kPem);
    ASSERT_TRUE(parsed.has_value());

    const auto slot_node_id = m_service->ResolveCertSlotNode(std::string{kAppResource}, kClientA);
    ASSERT_TRUE(slot_node_id.has_value());

    cert::CertRegistrationParams params;
    params.client_id = kClientA;
    params.parent_id = slot_node_id.value();
    params.slot_handle = cert::CertSlotHandle{};  // ephemeral — no slot backing, no fallback
    const auto registered = m_service->RegisterCertificate(params, *parsed);
    ASSERT_TRUE(registered.has_value());

    // No session CRL attached either: must resolve to "no CRL" success, not an
    // error, even though the ephemeral entry has no slot to fall back to.
    const auto resolved = m_service->ResolveCrlData(kClientA, registered->node_id);
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved.value(), nullptr);
}

TEST_F(CertManagementServiceTest, ResolveCrl_BareSlotNodeNotYetLoaded_ReadsCrlFromSlot)
{
    const std::vector<std::uint8_t> crl_bytes{0xC0U, 0xC1U, 0xC2U};
    ASSERT_TRUE(m_service
                    ->UpdateSlot(m_slot_handle,
                                 kClientA,
                                 cert::CrlData{crl_bytes, score::crypto::FormatType::kDer, MakeCrlMetadata(0x33U)})
                    .has_value());

    const auto slot_node_id = m_service->ResolveCertSlotNode(std::string{kAppResource}, kClientA);
    ASSERT_TRUE(slot_node_id.has_value());

    const auto resolved = m_service->ResolveCrlData(kClientA, slot_node_id.value());
    ASSERT_TRUE(resolved.has_value());
    ASSERT_NE(resolved.value(), nullptr);
    EXPECT_EQ((*resolved)->bytes, crl_bytes);
}

// A completely unknown node_id resolves neither to a CertDataNode nor a
// CertSlotDataNode, so both internal lookups fail and there is no source to
// report — this is treated as "no CRL available", not an error. Documents
// the actual (perhaps surprising) contract rather than asserting it is ideal;
// callers reach this function only after already resolving cert_node_id
// earlier in the same operation, so an unknown id should not occur in practice.
// A node that is neither a certificate nor a certificate slot is an error, not a missing CRL.
TEST_F(CertManagementServiceTest, ResolveCrl_UnknownNode_ReturnsInvalidResourceId)
{
    const auto resolved = m_service->ResolveCrlData(kClientA, 999U);
    ASSERT_FALSE(resolved.has_value());
    EXPECT_EQ(resolved.error(), score::crypto::daemon::common::DaemonErrorCode::kInvalidResourceId);
}

// ---------------------------------------------------------------------------
// CertManagementService::UpdateSlot/ClearSlotCrl push the CRL change into
// referencing trust stores internally; callers do not notify separately.
// Mirrors the UpdateSlot/ClearSlot trust-store-propagation tests above,
// for the CRL side.
// ---------------------------------------------------------------------------

TEST_F(CertManagementServiceTest, UpdateSlot_Crl_NotifiesTrustStoreCrlCache)
{
    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "test-roots";
    ts_cfg.members.push_back(
        cert::TrustStoreMemberConfig{std::string{kSlotName}, cert::TrustStoreMemberKind::kSharedStatic});

    ASSERT_TRUE(m_trust_store_manager->Load({ts_cfg}, m_registry, m_slot_manager).has_value());

    const auto ts_handle = m_trust_store_manager->ResolveByName("test-roots").value();
    auto store = m_trust_store_manager->GetStore(ts_handle);
    ASSERT_NE(store, nullptr);
    // Bind the store so that its cache is warm and the notification refreshes it.
    ASSERT_TRUE(m_trust_store_manager->AddRef(ts_handle, kClientA).has_value());

    // Force the handler into its loaded state before pushing the CRL update,
    // the same way a live trust store would already be loaded by the time a
    // client imports a CRL for one of its member slots.
    ASSERT_TRUE(store->GetAnchors().has_value());
    EXPECT_TRUE(store->GetCrls().value().empty());

    const std::vector<std::uint8_t> crl_bytes{0xC0U, 0xC1U, 0xC2U};
    const auto metadata = MakeCrlMetadata(0x44U);
    ASSERT_TRUE(
        m_service
            ->UpdateSlot(m_slot_handle, kClientA, cert::CrlData{crl_bytes, score::crypto::FormatType::kDer, metadata})
            .has_value());

    // No manual notify call — the service must have pushed it already.
    const auto crls = store->GetCrls().value();
    ASSERT_EQ(crls.size(), 1U);
    ASSERT_NE(crls[0], nullptr);
    EXPECT_EQ(crls[0]->bytes, crl_bytes);
    EXPECT_EQ(crls[0]->format, score::crypto::FormatType::kDer);
    ASSERT_TRUE(crls[0]->metadata.has_value());
    EXPECT_EQ(crls[0]->metadata->crl_number, metadata.crl_number);

    // The trust store shares the slot manager's snapshot instead of holding a copy.
    const auto slot_snapshot = m_service->GetSlotManager()->LoadCrlData(m_slot_handle, kClientA);
    ASSERT_TRUE(slot_snapshot.has_value());
    EXPECT_EQ(slot_snapshot.value().get(), crls[0].get());
}

TEST_F(CertManagementServiceTest, ClearSlotCrl_NotifiesTrustStoreCrlCache)
{
    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "test-roots";
    ts_cfg.members.push_back(
        cert::TrustStoreMemberConfig{std::string{kSlotName}, cert::TrustStoreMemberKind::kSharedStatic});

    ASSERT_TRUE(m_trust_store_manager->Load({ts_cfg}, m_registry, m_slot_manager).has_value());

    const auto ts_handle = m_trust_store_manager->ResolveByName("test-roots").value();
    auto store = m_trust_store_manager->GetStore(ts_handle);
    ASSERT_NE(store, nullptr);
    // Bind the store so that its cache is warm and the notification refreshes it.
    ASSERT_TRUE(m_trust_store_manager->AddRef(ts_handle, kClientA).has_value());

    const std::vector<std::uint8_t> crl_bytes{0xC0U, 0xC1U, 0xC2U};
    ASSERT_TRUE(m_service
                    ->UpdateSlot(m_slot_handle,
                                 kClientA,
                                 cert::CrlData{crl_bytes, score::crypto::FormatType::kDer, MakeCrlMetadata(0x55U)})
                    .has_value());
    ASSERT_EQ(store->GetCrls().value().size(), 1U);

    // Delete via the service — no manual notify call.
    ASSERT_TRUE(m_service->ClearSlotCrl(m_slot_handle, kClientA).has_value());

    EXPECT_TRUE(store->GetCrls().value().empty());
}

// ---------------------------------------------------------------------------
// CertSlotManager's CRL cache (HasCrl/GetCrlMetadata answered
// from one cached entry, LoadCrlData from a shared snapshot) must stay
// consistent across writes: a write that changes CRL state must be visible on
// the very next read, never a stale value.
// ---------------------------------------------------------------------------

TEST_F(CertManagementServiceTest, CrlCache_StaysConsistentAcrossImportDeleteAndRestore)
{
    auto* slot_manager = m_service->GetSlotManager().get();
    ASSERT_NE(slot_manager, nullptr);

    ASSERT_TRUE(slot_manager->HasCrl(m_slot_handle, kClientA).has_value());
    EXPECT_FALSE(slot_manager->HasCrl(m_slot_handle, kClientA).value());

    const std::vector<std::uint8_t> crl_bytes_1{0x01U, 0x02U};
    const auto metadata_1 = MakeCrlMetadata(0x66U);
    ASSERT_TRUE(m_service
                    ->UpdateSlot(m_slot_handle,
                                 kClientA,
                                 cert::CrlData{crl_bytes_1, score::crypto::FormatType::kDer, metadata_1})
                    .has_value());

    ASSERT_TRUE(slot_manager->HasCrl(m_slot_handle, kClientA).value());
    auto read_metadata = slot_manager->GetCrlMetadata(m_slot_handle, kClientA);
    ASSERT_TRUE(read_metadata.has_value());
    ASSERT_TRUE(read_metadata->has_value());
    EXPECT_EQ((*read_metadata)->crl_number, metadata_1.crl_number);

    // Re-import with different metadata — the cached value must not be reused.
    const std::vector<std::uint8_t> crl_bytes_2{0x03U, 0x04U, 0x05U};
    const auto metadata_2 = MakeCrlMetadata(0x77U);
    ASSERT_TRUE(m_service
                    ->UpdateSlot(m_slot_handle,
                                 kClientA,
                                 cert::CrlData{crl_bytes_2, score::crypto::FormatType::kPem, metadata_2})
                    .has_value());

    read_metadata = slot_manager->GetCrlMetadata(m_slot_handle, kClientA);
    ASSERT_TRUE(read_metadata.has_value());
    ASSERT_TRUE(read_metadata->has_value());
    EXPECT_EQ((*read_metadata)->crl_number, metadata_2.crl_number);

    // Delete must clear the cached state, not leave the prior CRL visible.
    ASSERT_TRUE(m_service->ClearSlotCrl(m_slot_handle, kClientA).has_value());
    ASSERT_TRUE(slot_manager->HasCrl(m_slot_handle, kClientA).has_value());
    EXPECT_FALSE(slot_manager->HasCrl(m_slot_handle, kClientA).value());
    read_metadata = slot_manager->GetCrlMetadata(m_slot_handle, kClientA);
    ASSERT_TRUE(read_metadata.has_value());
    EXPECT_FALSE(read_metadata->has_value());
}

// The certificate overload of UpdateSlot invalidates any existing CRL on the slot handler (the CRL
// was issued for the previous cert); CertSlotManager's CRL cache must
// reflect that, not continue to report the pre-replacement CRL as present.
TEST_F(CertManagementServiceTest, CrlCache_InvalidatedByCertificateUpdate)
{
    auto* slot_manager = m_service->GetSlotManager().get();
    ASSERT_NE(slot_manager, nullptr);

    const std::vector<std::uint8_t> crl_bytes{0x01U, 0x02U};
    ASSERT_TRUE(m_service
                    ->UpdateSlot(m_slot_handle,
                                 kClientA,
                                 cert::CrlData{crl_bytes, score::crypto::FormatType::kDer, MakeCrlMetadata(0x88U)})
                    .has_value());
    ASSERT_TRUE(slot_manager->HasCrl(m_slot_handle, kClientA).value());

    std::ifstream file(m_cert_updated_path, std::ios::binary);
    ASSERT_TRUE(file.is_open());
    const std::vector<std::uint8_t> updated_bytes{std::istreambuf_iterator<char>(file), {}};
    auto parsed_updated =
        m_parser->ParseCertificate(updated_bytes.data(), updated_bytes.size(), score::crypto::FormatType::kPem);
    ASSERT_TRUE(parsed_updated.has_value());
    ASSERT_TRUE(m_service->UpdateSlot(m_slot_handle, kClientA, **parsed_updated).has_value());

    ASSERT_TRUE(slot_manager->HasCrl(m_slot_handle, kClientA).has_value());
    EXPECT_FALSE(slot_manager->HasCrl(m_slot_handle, kClientA).value());
    const auto snapshot = slot_manager->LoadCrlData(m_slot_handle, kClientA);
    ASSERT_TRUE(snapshot.has_value());
    EXPECT_EQ(snapshot.value(), nullptr);
}

TEST_F(CertManagementServiceTest, CrlSnapshot_NullWhenSlotHasNoCrl)
{
    const auto snapshot = m_service->GetSlotManager()->LoadCrlData(m_slot_handle, kClientA);
    ASSERT_TRUE(snapshot.has_value());
    EXPECT_EQ(snapshot.value(), nullptr);
}

// A snapshot is shared among readers while any holds it and is never modified: a later
// import yields a new snapshot, and a holder of the previous one still sees the old CRL.
TEST_F(CertManagementServiceTest, CrlSnapshot_SharedBetweenReadersAndReplacedByImport)
{
    auto slot_manager = m_service->GetSlotManager();

    const std::vector<std::uint8_t> crl_bytes_1{0x01U, 0x02U};
    ASSERT_TRUE(m_service
                    ->UpdateSlot(m_slot_handle,
                                 kClientA,
                                 cert::CrlData{crl_bytes_1, score::crypto::FormatType::kDer, MakeCrlMetadata(0x11U)})
                    .has_value());

    const auto first = slot_manager->LoadCrlData(m_slot_handle, kClientA);
    const auto second = slot_manager->LoadCrlData(m_slot_handle, kClientA);
    ASSERT_TRUE(first.has_value() && second.has_value());
    ASSERT_NE(first.value(), nullptr);
    EXPECT_EQ(first.value().get(), second.value().get());
    EXPECT_EQ(first.value()->bytes, crl_bytes_1);

    const std::vector<std::uint8_t> crl_bytes_2{0x03U, 0x04U, 0x05U};
    const auto metadata_2 = MakeCrlMetadata(0x22U);
    ASSERT_TRUE(m_service
                    ->UpdateSlot(m_slot_handle,
                                 kClientA,
                                 cert::CrlData{crl_bytes_2, score::crypto::FormatType::kPem, metadata_2})
                    .has_value());

    const auto replaced = slot_manager->LoadCrlData(m_slot_handle, kClientA);
    ASSERT_TRUE(replaced.has_value());
    ASSERT_NE(replaced.value(), nullptr);
    EXPECT_NE(replaced.value().get(), first.value().get());
    EXPECT_EQ(replaced.value()->bytes, crl_bytes_2);
    EXPECT_EQ(replaced.value()->format, score::crypto::FormatType::kPem);
    ASSERT_TRUE(replaced.value()->metadata.has_value());
    EXPECT_EQ(replaced.value()->metadata->crl_number, metadata_2.crl_number);

    // The earlier holder's snapshot is unchanged.
    EXPECT_EQ(first.value()->bytes, crl_bytes_1);
}

// Presence and metadata queries answer from the same cached entry as the snapshot, so they
// agree with it after a load.
TEST_F(CertManagementServiceTest, CrlSnapshot_AgreesWithMetadataQueries)
{
    auto slot_manager = m_service->GetSlotManager();
    const auto metadata = MakeCrlMetadata(0x33U);
    const std::vector<std::uint8_t> crl_bytes{0x01U};
    ASSERT_TRUE(
        m_service
            ->UpdateSlot(m_slot_handle, kClientA, cert::CrlData{crl_bytes, score::crypto::FormatType::kPem, metadata})
            .has_value());

    const auto snapshot = slot_manager->LoadCrlData(m_slot_handle, kClientA);
    ASSERT_TRUE(snapshot.has_value());
    ASSERT_NE(snapshot.value(), nullptr);
    ASSERT_TRUE(slot_manager->HasCrl(m_slot_handle, kClientA).value());
    const auto read_metadata = slot_manager->GetCrlMetadata(m_slot_handle, kClientA);
    ASSERT_TRUE(read_metadata.has_value());
    ASSERT_TRUE(read_metadata->has_value());
    EXPECT_EQ((*read_metadata)->crl_number, snapshot.value()->metadata->crl_number);
}

// The certificate and CRL caches are invalidated independently: a CRL import does not discard a
// cached certificate, so a later load returns the same parsed object while a holder keeps it.
TEST_F(CertManagementServiceTest, CrlImport_KeepsCachedCertificate)
{
    auto slot_manager = m_service->GetSlotManager();
    const auto first = slot_manager->LoadCertificate(m_slot_handle, kClientA);
    ASSERT_TRUE(first.has_value());

    const std::vector<std::uint8_t> crl_bytes{0x01U, 0x02U};
    ASSERT_TRUE(m_service
                    ->UpdateSlot(m_slot_handle,
                                 kClientA,
                                 cert::CrlData{crl_bytes, score::crypto::FormatType::kDer, MakeCrlMetadata(0x99U)})
                    .has_value());

    const auto second = slot_manager->LoadCertificate(m_slot_handle, kClientA);
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(second.value().get(), first.value().get());
}

}  // namespace

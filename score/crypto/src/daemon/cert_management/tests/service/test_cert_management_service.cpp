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
// Uses a real DataManager, real CertSlotRegistry, real TrustStoreManager, and
// the real OpenSslCertParser + FileBackedSlotHandler backed by the central test
// vector at score/tests/test_vectors/certificate/certificate.pem.
//
// All cert bytes come from the central test-vector directory so that these
// tests share the same known-answer inputs as the integration and provider
// parser tests.
//
// Test subjects:
//   - Slot resolution and cert load via the executor call sequence
//     (ResolveCertSlot → ResolveSlotForOperation → LoadOrShare)
//   - ResolveCertForOperation round-trip
//   - Cert node release and subsequent unresolvability
//   - LoadOrShare deduplication — second call for the same slot shares the
//     existing CertEntry without a second handler LoadCertificate call
//   - Mediator-style client cleanup isolates clients — purging one leaves the other intact
//   - NotifySlotCertChanged propagates through TrustStoreManager anchor cache

#include "score/crypto/src/daemon/cert_management/core/cert_management_service.hpp"
#include "score/crypto/src/daemon/cert_management/slot/file_backed_slot_handler.hpp"
#include "score/crypto/src/daemon/cert_management/tests/test_environment.hpp"
#include "score/crypto/src/daemon/cert_management/truststore/trust_store_manager.hpp"
#include "score/crypto/src/daemon/common/storage/kv/kv_deployment_writer.hpp"
#include "score/crypto/src/daemon/data_manager/data_manager.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/cert_management/openssl_cert_parser.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>

namespace
{
namespace cert = score::crypto::daemon::cert_management;
namespace dm = score::crypto::daemon::data_manager;
namespace openssl_ns = score::crypto::daemon::provider::score_provider::openssl;
namespace storage = score::crypto::daemon::common::storage;

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
        cert::test::ConfigureTestLogging();
        m_dir = cert::test::TempDirectory("score_cert_mgmt_service");
        std::filesystem::remove_all(m_dir);
        std::filesystem::create_directories(m_dir);
        m_cert_path = m_dir / "root_ca.pem";
        m_cert_updated_path = m_dir / "root_ca_updated.pem";
        m_descriptor_path = m_dir / "root_ca.kv";

        ASSERT_TRUE(std::filesystem::copy_file(
            cert::test::TestVectorPath("score/tests/test_vectors/certificate/certificate.pem"),
            m_cert_path,
            std::filesystem::copy_options::overwrite_existing));
        ASSERT_TRUE(std::filesystem::copy_file(
            cert::test::TestVectorPath("score/tests/test_vectors/certificate/certificate_updated.pem"),
            m_cert_updated_path,
            std::filesystem::copy_options::overwrite_existing));

        // Write the KV descriptor pointing at the initial cert.
        storage::DeploymentDescriptor desc;
        desc.Set("certificate", "cert_path", m_cert_path.string());
        desc.Set("certificate", "cert_format", "pem");
        ASSERT_TRUE(storage::KvDeploymentWriter{}.Write(m_descriptor_path.string(), desc).has_value());

        m_parser = std::make_shared<openssl_ns::OpenSslCertParser>(score::crypto::daemon::common::ProviderId{1U});

        m_registry = std::make_shared<cert::CertSlotRegistry>();
        cert::CertSlotConfig slot_cfg;
        slot_cfg.slot_name = std::string{kSlotName};
        slot_cfg.storage_backend = "DEFAULT";
        slot_cfg.deployment_path = m_descriptor_path.string();
        slot_cfg.deployment_format = "kv";
        m_slot_handle = m_registry->RegisterSlot(slot_cfg);
        // Map uid=0 app resource "root_ca" → slot "test/root-ca"
        m_registry->RegisterAppResource(0U, std::string{kAppResource}, std::string{kSlotName});

        m_trust_store_manager = std::make_shared<cert::TrustStoreManager>();
        m_data_manager = std::make_shared<dm::DataManager>();

        m_service = std::make_shared<cert::CertManagementService>(
            m_data_manager, m_registry, m_trust_store_manager, [this](const cert::CertSlotConfig&) {
                return std::make_shared<cert::FileBackedSlotHandler>(m_parser);
            });
    }

    void TearDown() override
    {
        static_cast<void>(m_data_manager->deleteClientNodes(kClientA));
        static_cast<void>(m_data_manager->deleteClientNodes(kClientB));
        std::error_code ec;
        std::filesystem::remove_all(m_dir, ec);
    }

    // Mirror the executor call sequence: resolve the slot node, then load the cert.
    // Combines ResolveCertSlot → ResolveSlotForOperation → LoadOrShare.
    cert::CertDataNodeResult LoadCert(dm::ClientId client_id)
    {
        auto slot_res = m_service->ResolveCertSlot(std::string{kAppResource}, client_id);
        if (!slot_res.has_value())
            return {};
        const auto slot_node_id = slot_res.value();

        auto resolved = m_service->ResolveSlotForOperation(client_id, slot_node_id);
        if (!resolved.has_value())
            return {};

        cert::CertRegistrationParams params;
        params.client_id = client_id;
        params.parent_id = slot_node_id;
        params.slot_handle = resolved->handle;

        auto result = m_service->LoadOrShare(params, *resolved->handler, *resolved->config);
        if (!result.has_value())
            return {};
        return result.value();
    }

    std::filesystem::path m_dir;
    std::filesystem::path m_cert_path;
    std::filesystem::path m_cert_updated_path;
    std::filesystem::path m_descriptor_path;
    cert::CertSlotHandle m_slot_handle;

    std::shared_ptr<openssl_ns::OpenSslCertParser> m_parser;
    cert::CertSlotRegistry::Sptr m_registry;
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
    ASSERT_NE(result.entry, nullptr);
    EXPECT_EQ(result.entry->GetCertObject()->GetSubject(), kSubjectInitial);
    EXPECT_TRUE(result.entry->GetCertObject()->IsCA());
    EXPECT_EQ(result.entry->GetCertObject()->GetFingerprint().size(), 32U);
    EXPECT_EQ(result.entry->GetCertObject()->GetSkid().size(), 20U);
}

TEST_F(CertManagementServiceTest, ResolveCertForOperation_ReturnsSameObjectAsLoaded)
{
    const auto result = LoadCert(kClientA);
    ASSERT_NE(result.node_id, 0U);

    const auto resolved = m_service->ResolveCertForOperation(kClientA, result.node_id);
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ((*resolved)->GetSubject(), kSubjectInitial);
}

// ---------------------------------------------------------------------------
// Node release
// ---------------------------------------------------------------------------

TEST_F(CertManagementServiceTest, ReleaseCert_NodeBecomesUnresolvable)
{
    const auto result = LoadCert(kClientA);
    ASSERT_NE(result.node_id, 0U);

    ASSERT_TRUE(m_service->ReleaseCert(kClientA, result.node_id).has_value());

    EXPECT_FALSE(m_service->ResolveCertForOperation(kClientA, result.node_id).has_value());
}

TEST_F(CertManagementServiceTest, ReleaseCert_UnknownNodeId_ReturnsError)
{
    EXPECT_FALSE(m_service->ReleaseCert(kClientA, 999U).has_value());
}

// ---------------------------------------------------------------------------
// Deduplication — second call for the same slot must share the CertEntry
// ---------------------------------------------------------------------------

TEST_F(CertManagementServiceTest, LoadOrShare_SecondCallSharesRegistryEntry)
{
    const auto result1 = LoadCert(kClientA);
    ASSERT_NE(result1.node_id, 0U);
    ASSERT_NE(result1.entry, nullptr);

    const auto result2 = LoadCert(kClientA);
    ASSERT_NE(result2.node_id, 0U);
    ASSERT_NE(result2.entry, nullptr);

    // Separate data-manager nodes but the same live CertEntry.
    EXPECT_NE(result1.node_id, result2.node_id);
    EXPECT_EQ(result1.entry.get(), result2.entry.get());
}

// ---------------------------------------------------------------------------
// Slot-node deduplication
// ---------------------------------------------------------------------------

TEST_F(CertManagementServiceTest, ResolveCertSlot_SameClientAndResource_ReturnsSameNodeId)
{
    const auto id1 = m_service->ResolveCertSlot(std::string{kAppResource}, kClientA);
    const auto id2 = m_service->ResolveCertSlot(std::string{kAppResource}, kClientA);

    ASSERT_TRUE(id1.has_value());
    ASSERT_TRUE(id2.has_value());
    EXPECT_EQ(id1.value(), id2.value());
}

TEST_F(CertManagementServiceTest, ResolveCertSlot_UnknownResource_ReturnsError)
{
    EXPECT_FALSE(m_service->ResolveCertSlot("no_such_resource", kClientA).has_value());
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
    EXPECT_FALSE(m_service->ResolveCertForOperation(kClientA, result_a.node_id).has_value());
    // Client B must be unaffected.
    EXPECT_TRUE(m_service->ResolveCertForOperation(kClientB, result_b.node_id).has_value());
}

// ---------------------------------------------------------------------------
// Trust-store propagation
// ---------------------------------------------------------------------------

TEST_F(CertManagementServiceTest, NotifySlotCertChanged_RefreshesAnchorSubjectInTrustStore)
{
    // Wire up a trust store backed by the same slot.
    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "test-roots";
    ts_cfg.members.push_back(
        cert::TrustStoreMemberConfig{std::string{kSlotName}, cert::TrustStoreMemberKind::kSharedStatic});

    m_trust_store_manager->Load({ts_cfg}, m_registry, [this](const cert::CertSlotConfig&) {
        return std::make_shared<cert::FileBackedSlotHandler>(m_parser);
    });

    const auto ts_id = m_trust_store_manager->ResolveByName("test-roots");
    auto store = m_trust_store_manager->GetStore(ts_id);
    ASSERT_NE(store, nullptr);

    // Verify the initial anchor subject.
    auto initial = store->GetAnchors();
    ASSERT_TRUE(initial.has_value());
    ASSERT_EQ(initial->size(), 1U);
    EXPECT_EQ((*initial)[0]->GetSubject(), kSubjectInitial);

    // Replace the cert on disk — point the descriptor at the updated cert.
    storage::DeploymentDescriptor updated_desc;
    updated_desc.Set("certificate", "cert_path", m_cert_updated_path.string());
    updated_desc.Set("certificate", "cert_format", "pem");
    ASSERT_TRUE(storage::KvDeploymentWriter{}.Write(m_descriptor_path.string(), updated_desc).has_value());

    // Fan-out the change notification through the service.
    m_service->NotifySlotCertChanged(m_slot_handle);

    // The anchor cache must reflect the new cert.
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

// ---------------------------------------------------------------------------
// Ephemeral cert registration — RegisterCertMaterial with an invalid slot
// handle (no persistent backing). The caller supplies a pre-parsed CertObject;
// the service creates a CertDataNode under the given parent and registers the
// entry in the ephemeral (non-slot-keyed) section of the cert registry.
// ---------------------------------------------------------------------------

TEST_F(CertManagementServiceTest, RegisterCertMaterial_EphemeralPath_CreatesResolvableNode)
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
    const auto slot_node_id = m_service->ResolveCertSlot(std::string{kAppResource}, kClientA);
    ASSERT_TRUE(slot_node_id.has_value());

    // Pass an invalid CertSlotHandle to register as ephemeral (no slot backing).
    cert::CertRegistrationParams params;
    params.client_id = kClientA;
    params.parent_id = slot_node_id.value();
    params.slot_handle = cert::CertSlotHandle{};

    const auto result = m_service->RegisterCertMaterial(params, *parsed);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->node_id, 0U);
    ASSERT_NE(result->entry, nullptr);
    EXPECT_EQ(result->entry->GetCertObject()->GetSubject(), kSubjectInitial);

    // The node must be resolvable immediately after registration.
    const auto resolved = m_service->ResolveCertForOperation(kClientA, result->node_id);
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ((*resolved)->GetSubject(), kSubjectInitial);

    // Releasing the ephemeral node must make it unresolvable.
    ASSERT_TRUE(m_service->ReleaseCert(kClientA, result->node_id).has_value());
    EXPECT_FALSE(m_service->ResolveCertForOperation(kClientA, result->node_id).has_value());
}

// ---------------------------------------------------------------------------
// ResolveCertEntryForOperation — returns the CertEntry behind a cert node.
// Enables callers to access session CRL state alongside the CertObject.
// ---------------------------------------------------------------------------

TEST_F(CertManagementServiceTest, ResolveCertEntryForOperation_ReturnsSameEntryAsLoaded)
{
    const auto result = LoadCert(kClientA);
    ASSERT_NE(result.node_id, 0U);
    ASSERT_NE(result.entry, nullptr);

    const auto entry_res = m_service->ResolveCertEntryForOperation(kClientA, result.node_id);
    ASSERT_TRUE(entry_res.has_value());
    // Must be the exact same CertEntry (shared ownership), not a copy.
    EXPECT_EQ(entry_res->get(), result.entry.get());
    // The resolved entry must expose the same cert object.
    EXPECT_EQ((*entry_res)->GetCertObject()->GetSubject(), kSubjectInitial);
}

TEST_F(CertManagementServiceTest, ResolveCertEntryForOperation_UnknownNode_ReturnsError)
{
    EXPECT_FALSE(m_service->ResolveCertEntryForOperation(kClientA, 999U).has_value());
}

// ---------------------------------------------------------------------------
// AttachSessionCrl — stores CRL bytes in-memory on CertEntry; no disk write.
// Subsequent GetSessionCrl() on the entry returns the attached bytes.
// ---------------------------------------------------------------------------

TEST_F(CertManagementServiceTest, AttachSessionCrl_StoresInMemoryNotOnDisk)
{
    const auto result = LoadCert(kClientA);
    ASSERT_NE(result.node_id, 0U);

    // No CRL on disk before the call.
    EXPECT_FALSE(result.entry->HasSessionCrl());

    const std::vector<std::uint8_t> crl_bytes{0xC0U, 0xC1U, 0xC2U};
    ASSERT_TRUE(
        m_service->AttachSessionCrl(kClientA, result.node_id, crl_bytes, score::crypto::FormatType::kDer).has_value());

    // CRL must be accessible in-memory through the entry.
    EXPECT_TRUE(result.entry->HasSessionCrl());
    const auto session_crl = result.entry->GetSessionCrl();
    ASSERT_TRUE(session_crl.has_value());
    EXPECT_EQ(*session_crl, crl_bytes);
    EXPECT_EQ(result.entry->GetSessionCrlFormat(), score::crypto::FormatType::kDer);

    // No CRL file must have been written to disk.
    EXPECT_FALSE(std::filesystem::exists(m_dir / "root_ca.crl"));
}

TEST_F(CertManagementServiceTest, AttachSessionCrl_UnknownNode_ReturnsError)
{
    const std::vector<std::uint8_t> crl_bytes{0x01U};
    EXPECT_FALSE(m_service->AttachSessionCrl(kClientA, 999U, crl_bytes, score::crypto::FormatType::kDer).has_value());
}

}  // namespace

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
 ******************************************************************************/
//
// Component-level tests for TrustStoreManager.
//
// Uses the real SlotHandlerFactory, OpenSSL provider, file-backed slot handler,
// and central test vectors to exercise trust-store anchor loading, eviction, and mutations.
//
// All cert bytes come from score/tests/test_vectors/certificate/basic/ and all slot
// state is backed by KV descriptor files in a per-test temp directory.
//
// Test subjects:
//   - Lazy anchor loading and slot membership index
//   - Per-client AddRef/ReleaseRef — cache is evicted only when ALL clients release
//   - CleanupClient — drops all refs for a crashed client and evicts the cache
//   - DisableMember / EnableMember — toggle anchor visibility synchronously
//   - Two stores sharing one slot — same CertObject instance, single disk read
//   - AddMember — stores a cert into an empty exclusive slot, persists to disk
//   - RemoveMember — removes anchor by real SHA-256 fingerprint
//   - AcknowledgeMemberUpdate — re-enables a disabled slot with fresh load
//   - ConditionalExternal — slot updates disable members until acknowledged

#include "score/crypto/src/daemon/cert_management/slot/cert_slot_manager.hpp"
#include "score/crypto/src/daemon/cert_management/slot/file_backed_slot_handler.hpp"
#include "score/crypto/src/daemon/cert_management/slot/slot_handler_factory.hpp"
#include "score/crypto/src/daemon/cert_management/truststore/trust_store_manager.hpp"
#include "score/crypto/src/daemon/common/storage/kv/kv_deployment_writer.hpp"
#include "score/crypto/src/daemon/provider/cert_management/i_cert_parser.hpp"
#include "score/crypto/src/daemon/provider/provider_manager.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/cert_management/openssl_cert_parser.hpp"
#include "score/tests/utility/test_utility.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace
{
namespace cert = score::crypto::daemon::cert_management;
namespace dm = score::crypto::daemon::data_manager;
namespace config = score::crypto::daemon::config;
namespace provider = score::crypto::daemon::provider;
namespace openssl_ns = score::crypto::daemon::provider::score_provider::openssl;
namespace storage = score::crypto::daemon::common::storage;
namespace common = score::crypto::daemon::common;
using Error = score::crypto::daemon::common::DaemonErrorCode;

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

// Test-vector subjects — match certificate_manifest.json
static constexpr std::string_view kSubjectInitial = "CN=cert-management-test,O=Eclipse";
static constexpr std::string_view kSubjectUpdated = "CN=cert-management-updated,O=Eclipse";

// client_id layout: upper 32 bits = UID, lower 32 bits = PID.
// UID=0 matches allowed_write_uids = {0U} in trust-store access policies.
static constexpr dm::ClientId kClientA = 1U;  // uid=0, pid=1
static constexpr dm::ClientId kClientB = 2U;  // uid=0, pid=2

// ---------------------------------------------------------------------------
// Common fixture — one temp directory per test, two cert slots pre-configured.
//
//  "root-anchor"  : KV descriptor + certificate.pem (kSubjectInitial)
//  "empty-anchor" : KV descriptor with cert_path set, but file absent
//
// Tests that need a second cert ("certificate_updated.pem") copy it over
// "root-anchor"'s cert file after capturing the initial anchor, simulating an
// on-disk rotation observed after cache eviction.
// ---------------------------------------------------------------------------

class TrustStoreManagerTest : public ::testing::Test
{
  protected:
    static void SetUpTestSuite()
    {
        s_provider_manager = std::make_shared<provider::ProviderManager>(config::ProviderInitConfig{});
        s_parser = std::make_shared<openssl_ns::OpenSslCertParser>(common::ProviderId{0U});
        auto openssl_provider = std::make_shared<OpenSslParserProvider>(s_parser);
        ASSERT_TRUE(
            s_provider_manager->RegisterProvider("OPENSSL", openssl_provider, common::CryptoProviderType::SOFTWARE));
        ASSERT_TRUE(s_provider_manager->Initialize());
    }

    static void TearDownTestSuite()
    {
        s_parser.reset();
        if (s_provider_manager)
        {
            s_provider_manager->Shutdown();
            s_provider_manager.reset();
        }
    }

    void SetUp() override
    {
        m_dir = ::tests::utility::TempDirectory("score_ts_mgr_test");
        std::filesystem::remove_all(m_dir);
        std::filesystem::create_directories(m_dir);

        m_parser = s_parser;

        // root-anchor: slot backed by the initial test vector cert.
        m_root_cert = m_dir / "root_ca.pem";
        m_root_slot_kv = m_dir / "root_ca.kv";
        ASSERT_TRUE(std::filesystem::copy_file("score/tests/test_vectors/certificate/basic/certificate.pem",
                                               m_root_cert,
                                               std::filesystem::copy_options::overwrite_existing));
        WriteSlotDescriptor(m_root_slot_kv, m_root_cert);

        // empty-anchor: descriptor ready, but cert file not created yet.
        m_empty_cert = m_dir / "empty_ca.pem";
        m_empty_slot_kv = m_dir / "empty_ca.kv";
        WriteSlotDescriptor(m_empty_slot_kv, m_empty_cert);
        // m_empty_cert is intentionally NOT created here.
    }

    void TearDown() override
    {
        std::error_code ec;
        std::filesystem::remove_all(m_dir, ec);
    }

    void WriteSlotDescriptor(const std::filesystem::path& kv, const std::filesystem::path& cert_file)
    {
        storage::DeploymentDescriptor desc;
        desc.Set("certificate", "cert_path", cert_file.string());
        desc.Set("certificate", "cert_format", "pem");
        ASSERT_TRUE(storage::KvDeploymentWriter{}.Write(kv.string(), desc).has_value());
    }

    cert::CertSlotManager::Sptr MakeSlotManager(cert::CertSlotRegistry::Sptr registry)
    {
        auto factory = std::make_shared<cert::SlotHandlerFactory>(s_provider_manager);
        return std::make_shared<cert::CertSlotManager>(std::move(registry), std::move(factory));
    }

    // MakeSlotConfig — for tests that mutate state (overwrite cert file, AddMember, etc.)
    // Points to a per-test temp directory copy so the committed test vectors stay clean.
    cert::CertSlotConfig MakeSlotConfig(const std::string& name, const std::filesystem::path& kv) const
    {
        cert::CertSlotConfig cfg;
        cfg.slot_name = name;
        cfg.storage_backend = "DEFAULT";
        cfg.deployment_path = kv.string();
        cfg.deployment_format = "kv";
        return cfg;
    }

    // StaticSlotConfig — for read-only tests that never overwrite cert files.
    // Uses the per-test descriptor and certificate created in SetUp().
    cert::CertSlotConfig StaticSlotConfig(const std::string& name) const
    {
        cert::CertSlotConfig cfg;
        cfg.slot_name = name;
        cfg.storage_backend = "DEFAULT";
        cfg.deployment_path = m_root_slot_kv.string();
        cfg.deployment_format = "kv";
        return cfg;
    }

    // Parse the cert at the given path and return the first CertObject.
    cert::CertObject::Sptr ParseCert(const std::filesystem::path& path) const
    {
        std::ifstream file(path, std::ios::binary);
        std::vector<std::uint8_t> bytes{std::istreambuf_iterator<char>(file), {}};
        auto result = m_parser->ParseCertificate(bytes.data(), bytes.size(), score::crypto::FormatType::kPem);
        return result.has_value() ? *result : nullptr;
    }

    std::filesystem::path m_dir;
    std::filesystem::path m_root_cert;
    std::filesystem::path m_root_slot_kv;
    std::filesystem::path m_empty_cert;
    std::filesystem::path m_empty_slot_kv;
    static provider::ProviderManager::Sptr s_provider_manager;
    static std::shared_ptr<openssl_ns::OpenSslCertParser> s_parser;
    std::shared_ptr<openssl_ns::OpenSslCertParser> m_parser;
};

provider::ProviderManager::Sptr TrustStoreManagerTest::s_provider_manager;
std::shared_ptr<openssl_ns::OpenSslCertParser> TrustStoreManagerTest::s_parser;

// ---------------------------------------------------------------------------
// Basic: lazy anchor loading and slot membership index
// ---------------------------------------------------------------------------

TEST_F(TrustStoreManagerTest, LoadsAnchorsLazilyAndBuildsSlotMembershipIndex)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_mgmt__trust_stores");
    RecordProperty("Description",
                   "Builds trust-store membership from typed certificate-slot references and lazily loads its anchor.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    auto registry = std::make_shared<cert::CertSlotRegistry>();
    const auto slot = registry->RegisterSlot(StaticSlotConfig("root-anchor"));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "tls-roots";
    ts_cfg.members.push_back(cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kSharedStatic});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());

    // Membership index is built at Load() time without touching cert bytes.
    ASSERT_EQ(manager.GetMembershipsForSlot(slot).size(), 1U);
    EXPECT_EQ(manager.GetMembershipsForSlot(slot)[0], cert::TrustStoreHandle{0U});

    // Anchors are loaded lazily on the first GetAnchors() call.
    auto store = manager.GetStore(cert::TrustStoreHandle{0U});
    ASSERT_NE(store, nullptr);
    auto anchors = store->GetAnchors();
    ASSERT_TRUE(anchors.has_value());
    ASSERT_EQ(anchors->size(), 1U);
    EXPECT_EQ((*anchors)[0]->GetSubject(), kSubjectInitial);
    EXPECT_EQ((*anchors)[0]->GetFingerprint().size(), score::crypto::kSha256FingerprintSize);
}

// ---------------------------------------------------------------------------
// GetMemberSlotHandles / GetMemberSnapshot — list a trust store's occupied
// member identities, then resolve each member's detail individually.
// ---------------------------------------------------------------------------

TEST_F(TrustStoreManagerTest, GetMemberSlotHandles_ReturnsOnlyOccupiedMembers)
{
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    const auto occupied_slot = registry->RegisterSlot(StaticSlotConfig("root-anchor"));
    static_cast<void>(registry->RegisterSlot(MakeSlotConfig("empty-anchor", m_empty_slot_kv)));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "tls-roots";
    ts_cfg.members.push_back(cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kSharedStatic});
    ts_cfg.members.push_back(cert::TrustStoreMemberConfig{"empty-anchor", cert::TrustStoreMemberKind::kSharedStatic});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());

    const auto result = manager.GetMemberSlotHandles(cert::TrustStoreHandle{0U});
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->size(), 1U);
    EXPECT_EQ((*result)[0], occupied_slot);
}

TEST_F(TrustStoreManagerTest, GetMemberSnapshot_ReturnsMemberDetail)
{
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    const auto slot = registry->RegisterSlot(StaticSlotConfig("root-anchor"));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "tls-roots";
    ts_cfg.members.push_back(cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kSharedStatic});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());

    const auto single = manager.GetMemberSnapshot(cert::TrustStoreHandle{0U}, slot);
    ASSERT_TRUE(single.has_value());
    EXPECT_EQ(single->slot_handle, slot);
    EXPECT_EQ(single->subject, kSubjectInitial);
    EXPECT_EQ(single->status, score::crypto::MemberStatus::kEnabled);
}

TEST_F(TrustStoreManagerTest, GetMemberSnapshot_SlotNotAMember_ReturnsInvalidResourceId)
{
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    static_cast<void>(registry->RegisterSlot(StaticSlotConfig("root-anchor")));
    const auto other_slot = registry->RegisterSlot(MakeSlotConfig("empty-anchor", m_empty_slot_kv));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "tls-roots";
    ts_cfg.members.push_back(cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kSharedStatic});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());

    const auto result = manager.GetMemberSnapshot(cert::TrustStoreHandle{0U}, other_slot);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kInvalidResourceId);
}

// ---------------------------------------------------------------------------
// Rejection of unknown handles — no I/O needed.
// ---------------------------------------------------------------------------

TEST(TrustStoreManagerStandaloneTest, RejectsUnknownStoreAndSlotHandles)
{
    cert::TrustStoreManager manager;
    EXPECT_EQ(manager.GetStore(cert::TrustStoreHandle{0U}), nullptr);
    EXPECT_EQ(manager.GetMembershipsForSlot(cert::CertSlotHandle{4U}).size(), 0U);
}

TEST(TrustStoreManagerStandaloneTest, GetMemberSlotHandlesAndSnapshot_RejectUnknownStoreHandle)
{
    cert::TrustStoreManager manager;
    EXPECT_FALSE(manager.GetMemberSlotHandles(cert::TrustStoreHandle{0U}).has_value());
    EXPECT_FALSE(manager.GetMemberSnapshot(cert::TrustStoreHandle{0U}, cert::CertSlotHandle{0U}).has_value());
}

// ---------------------------------------------------------------------------
// Per-client AddRef/ReleaseRef — anchor cache is evicted only when ALL clients
// release. After eviction, the next GetAnchors() reloads from disk.
//
// To make eviction observable without stub counters, the cert file is replaced
// on disk after the initial load. Releasing one client does not evict (the
// other still holds a ref), so GetAnchors() returns the old subject. Only
// after both clients release does the cache evict; the next GetAnchors() reads
// the new cert from disk.
// ---------------------------------------------------------------------------

TEST_F(TrustStoreManagerTest, PerClientAddRef_DoesNotEvictCacheWhileOtherClientHoldsRef)
{
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    static_cast<void>(registry->RegisterSlot(MakeSlotConfig("root-anchor", m_root_slot_kv)));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "tls-roots";
    ts_cfg.members.push_back(cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kSharedStatic});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());

    const auto ts_handle = manager.ResolveByName("tls-roots").value();
    auto store = manager.GetStore(ts_handle);
    ASSERT_NE(store, nullptr);

    // Binding warms the cache. The result is dropped after each read so that the anchor's
    // strong ref lives only inside TrustStoreHandler (not in the test frame).
    ASSERT_TRUE(manager.AddRef(ts_handle, kClientA).has_value());
    ASSERT_TRUE(manager.AddRef(ts_handle, kClientB).has_value());
    {
        auto anchors = store->GetAnchors();
        ASSERT_TRUE(anchors.has_value());
        EXPECT_EQ((*anchors)[0]->GetSubject(), kSubjectInitial);
    }

    // Rotate cert on disk — subsequent reloads will see kSubjectUpdated.
    ASSERT_TRUE(std::filesystem::copy_file("score/tests/test_vectors/certificate/basic/certificate_updated.pem",
                                           m_root_cert,
                                           std::filesystem::copy_options::overwrite_existing));

    // Release kClientA — kClientB still holds a ref; no eviction.
    manager.ReleaseRef(ts_handle, kClientA);
    {
        auto anchors = store->GetAnchors();
        ASSERT_TRUE(anchors.has_value());
        // Cache is intact (not evicted) — stale cert A still returned.
        EXPECT_EQ((*anchors)[0]->GetSubject(), kSubjectInitial);
    }

    // Release kClientB — last ref gone; cache is evicted (m_slots cleared).
    manager.ReleaseRef(ts_handle, kClientB);

    // Next GetAnchors() reloads from disk — must now see the rotated cert.
    auto reloaded = store->GetAnchors();
    ASSERT_TRUE(reloaded.has_value());
    ASSERT_EQ(reloaded->size(), 1U);
    EXPECT_EQ((*reloaded)[0]->GetSubject(), kSubjectUpdated);
}

// ---------------------------------------------------------------------------
// CleanupClient — drops all refs for a disconnected/crashed client and evicts
// the anchor cache when no other client holds refs.
// ---------------------------------------------------------------------------

TEST_F(TrustStoreManagerTest, CleanupClient_ReleasesAllRefsAndEvictsCache)
{
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    static_cast<void>(registry->RegisterSlot(MakeSlotConfig("root-anchor", m_root_slot_kv)));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "tls-roots";
    ts_cfg.members.push_back(cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kSharedStatic});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());

    const auto ts_handle = manager.ResolveByName("tls-roots").value();
    auto store = manager.GetStore(ts_handle);
    ASSERT_NE(store, nullptr);

    // Simulate two open verification contexts for kClientA.
    ASSERT_TRUE(manager.AddRef(ts_handle, kClientA).has_value());
    ASSERT_TRUE(manager.AddRef(ts_handle, kClientA).has_value());

    // Read through the warm cache and drop the caller strong ref.
    {
        auto anchors = store->GetAnchors();
        ASSERT_TRUE(anchors.has_value());
        EXPECT_EQ((*anchors)[0]->GetSubject(), kSubjectInitial);
    }

    // Rotate cert on disk.
    ASSERT_TRUE(std::filesystem::copy_file("score/tests/test_vectors/certificate/basic/certificate_updated.pem",
                                           m_root_cert,
                                           std::filesystem::copy_options::overwrite_existing));

    // Crash cleanup drops all kClientA refs — no other client holds refs.
    manager.CleanupClient(kClientA);

    // Next GetAnchors() must reload from disk and return the rotated cert.
    auto reloaded = store->GetAnchors();
    ASSERT_TRUE(reloaded.has_value());
    ASSERT_EQ(reloaded->size(), 1U);
    EXPECT_EQ((*reloaded)[0]->GetSubject(), kSubjectUpdated);
}

// ---------------------------------------------------------------------------
// Cache lifecycle — the cache is warm only while a client holds the store.
// ---------------------------------------------------------------------------

// A read on a store that no client holds resolves the members and does not cache them, so a
// change on disk is visible to the next read.
TEST_F(TrustStoreManagerTest, UnboundRead_ResolvesWithoutCaching)
{
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    static_cast<void>(registry->RegisterSlot(MakeSlotConfig("root-anchor", m_root_slot_kv)));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "tls-roots";
    ts_cfg.members.push_back(cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kSharedStatic});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());
    auto store = manager.GetStore(manager.ResolveByName("tls-roots").value());
    ASSERT_NE(store, nullptr);

    {
        auto anchors = store->GetAnchors();
        ASSERT_TRUE(anchors.has_value());
        ASSERT_EQ(anchors->size(), 1U);
        EXPECT_EQ((*anchors)[0]->GetSubject(), kSubjectInitial);
    }

    ASSERT_TRUE(std::filesystem::copy_file("score/tests/test_vectors/certificate/basic/certificate_updated.pem",
                                           m_root_cert,
                                           std::filesystem::copy_options::overwrite_existing));

    auto reread = store->GetAnchors();
    ASSERT_TRUE(reread.has_value());
    ASSERT_EQ(reread->size(), 1U);
    EXPECT_EQ((*reread)[0]->GetSubject(), kSubjectUpdated);
}

// A member whose certificate exists but cannot be read makes the bind fail. The failure is
// returned instead of silently dropping the member, no reference is kept, and a read reports
// the same failure.
TEST_F(TrustStoreManagerTest, AddRef_MemberLoadFailure_ReturnsErrorAndKeepsNoReference)
{
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    static_cast<void>(registry->RegisterSlot(MakeSlotConfig("root-anchor", m_root_slot_kv)));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "tls-roots";
    ts_cfg.members.push_back(cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kSharedStatic});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());
    const auto ts_handle = manager.ResolveByName("tls-roots").value();
    auto store = manager.GetStore(ts_handle);
    ASSERT_NE(store, nullptr);

    {
        std::ofstream corrupt(m_root_cert, std::ios::binary | std::ios::trunc);
        corrupt << "not a certificate";
    }

    EXPECT_FALSE(manager.AddRef(ts_handle, kClientA).has_value());
    EXPECT_FALSE(store->GetAnchors().has_value());

    // Repair the member and bind with another client, then rotate the certificate and release.
    // The cache is cleared on that release only if the failed bind left no reference behind.
    ASSERT_TRUE(std::filesystem::copy_file("score/tests/test_vectors/certificate/basic/certificate.pem",
                                           m_root_cert,
                                           std::filesystem::copy_options::overwrite_existing));
    ASSERT_TRUE(manager.AddRef(ts_handle, kClientB).has_value());
    ASSERT_TRUE(std::filesystem::copy_file("score/tests/test_vectors/certificate/basic/certificate_updated.pem",
                                           m_root_cert,
                                           std::filesystem::copy_options::overwrite_existing));
    manager.ReleaseRef(ts_handle, kClientB);

    auto reloaded = store->GetAnchors();
    ASSERT_TRUE(reloaded.has_value());
    ASSERT_EQ(reloaded->size(), 1U);
    EXPECT_EQ((*reloaded)[0]->GetSubject(), kSubjectUpdated);
}

// An empty member slot is a valid state, not a failure: the bind succeeds with no anchor for it.
TEST_F(TrustStoreManagerTest, AddRef_EmptyMemberSlot_Succeeds)
{
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    static_cast<void>(registry->RegisterSlot(MakeSlotConfig("empty-anchor", m_empty_slot_kv)));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "mutable-store";
    ts_cfg.members.push_back(
        cert::TrustStoreMemberConfig{"empty-anchor", cert::TrustStoreMemberKind::kExclusiveMutable});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());
    const auto ts_handle = manager.ResolveByName("mutable-store").value();

    ASSERT_TRUE(manager.AddRef(ts_handle, kClientA).has_value());
    const auto anchors = manager.GetStore(ts_handle)->GetAnchors();
    ASSERT_TRUE(anchors.has_value());
    EXPECT_TRUE(anchors->empty());
}

// A mutation on a store that no client holds changes persisted state only. It must not leave
// the added certificate cached in the handler.
TEST_F(TrustStoreManagerTest, AddMember_ColdStore_DoesNotRetainAnchor)
{
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    static_cast<void>(registry->RegisterSlot(MakeSlotConfig("empty-anchor", m_empty_slot_kv)));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "mutable-store";
    ts_cfg.access_policy.allowed_write_uids = {0U};
    ts_cfg.members.push_back(
        cert::TrustStoreMemberConfig{"empty-anchor", cert::TrustStoreMemberKind::kExclusiveMutable});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());
    const auto ts_handle = manager.ResolveByName("mutable-store").value();

    auto cert = ParseCert(m_root_cert);
    ASSERT_NE(cert, nullptr);
    const std::weak_ptr<cert::CertObject> weak = cert;
    ASSERT_TRUE(manager.AddMember(ts_handle, cert, kClientA).has_value());
    cert.reset();
    EXPECT_TRUE(weak.expired());

    // The member is still visible to a read, which resolves it from the slot.
    const auto anchors = manager.GetStore(ts_handle)->GetAnchors();
    ASSERT_TRUE(anchors.has_value());
    EXPECT_EQ(anchors->size(), 1U);
}

// The same mutation on a store a client holds updates the cache.
TEST_F(TrustStoreManagerTest, AddMember_WarmStore_UpdatesCache)
{
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    static_cast<void>(registry->RegisterSlot(MakeSlotConfig("empty-anchor", m_empty_slot_kv)));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "mutable-store";
    ts_cfg.access_policy.allowed_write_uids = {0U};
    ts_cfg.members.push_back(
        cert::TrustStoreMemberConfig{"empty-anchor", cert::TrustStoreMemberKind::kExclusiveMutable});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());
    const auto ts_handle = manager.ResolveByName("mutable-store").value();
    ASSERT_TRUE(manager.AddRef(ts_handle, kClientA).has_value());

    auto cert = ParseCert(m_root_cert);
    ASSERT_NE(cert, nullptr);
    const std::weak_ptr<cert::CertObject> weak = cert;
    ASSERT_TRUE(manager.AddMember(ts_handle, cert, kClientA).has_value());
    cert.reset();
    EXPECT_FALSE(weak.expired());

    const auto anchors = manager.GetStore(ts_handle)->GetAnchors();
    ASSERT_TRUE(anchors.has_value());
    EXPECT_EQ(anchors->size(), 1U);
}

// ---------------------------------------------------------------------------
// Startup validation — a store that cannot be used reports an error instead of running with a
// subset of its members or with default state.
// ---------------------------------------------------------------------------

TEST_F(TrustStoreManagerTest, Load_DuplicateStoreName_IsRejectedAndChangesNothing)
{
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    static_cast<void>(registry->RegisterSlot(MakeSlotConfig("root-anchor", m_root_slot_kv)));

    cert::TrustStoreConfig first;
    first.store_name = "tls-roots";
    first.members.push_back(cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kSharedStatic});
    const auto second = first;

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({first}, registry, MakeSlotManager(registry)).has_value());

    const auto rejected = manager.Load({first, second}, registry, MakeSlotManager(registry));
    ASSERT_FALSE(rejected.has_value());
    EXPECT_EQ(rejected.error(), Error::kInvalidArgument);

    // The configuration that was loaded before is still in place.
    EXPECT_TRUE(manager.ResolveByName("tls-roots").has_value());
}

TEST_F(TrustStoreManagerTest, Load_EmptyStoreName_IsRejected)
{
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    static_cast<void>(registry->RegisterSlot(MakeSlotConfig("root-anchor", m_root_slot_kv)));

    cert::TrustStoreConfig unnamed;
    unnamed.members.push_back(cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kSharedStatic});

    cert::TrustStoreManager manager;
    const auto rejected = manager.Load({unnamed}, registry, MakeSlotManager(registry));
    ASSERT_FALSE(rejected.has_value());
    EXPECT_EQ(rejected.error(), Error::kInvalidArgument);
}

TEST_F(TrustStoreManagerTest, ResolveByName_UnknownName_ReturnsInvalidResourceId)
{
    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({}, std::make_shared<cert::CertSlotRegistry>(), {}).has_value());

    const auto resolved = manager.ResolveByName("nothing");
    ASSERT_FALSE(resolved.has_value());
    EXPECT_EQ(resolved.error(), Error::kInvalidResourceId);
}

// A member that does not name a configured slot makes the whole store unusable. Every
// operation that would have used the store reports it, so no client runs with a subset.
TEST_F(TrustStoreManagerTest, UnresolvedMember_MakesStoreInvalid)
{
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    static_cast<void>(registry->RegisterSlot(MakeSlotConfig("root-anchor", m_root_slot_kv)));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "tls-roots";
    ts_cfg.members.push_back(cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kSharedStatic});
    ts_cfg.members.push_back(cert::TrustStoreMemberConfig{"no-such-slot", cert::TrustStoreMemberKind::kSharedStatic});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());
    manager.RegisterAppResource(0U, "tls", "tls-roots");

    const auto ts_handle = manager.ResolveByName("tls-roots").value();
    auto store = manager.GetStore(ts_handle);
    ASSERT_NE(store, nullptr);

    const auto anchors = store->GetAnchors();
    ASSERT_FALSE(anchors.has_value());
    EXPECT_EQ(anchors.error(), Error::kTrustStoreInvalid);

    const auto bound = manager.AddRef(ts_handle, kClientA);
    ASSERT_FALSE(bound.has_value());
    EXPECT_EQ(bound.error(), Error::kTrustStoreInvalid);

    const auto resolved = manager.ResolveAppResource("tls", kClientA);
    ASSERT_FALSE(resolved.has_value());
    EXPECT_EQ(resolved.error(), Error::kTrustStoreInvalid);
}

TEST_F(TrustStoreManagerTest, DuplicateMember_MakesStoreInvalid)
{
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    static_cast<void>(registry->RegisterSlot(MakeSlotConfig("root-anchor", m_root_slot_kv)));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "tls-roots";
    ts_cfg.members.push_back(cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kSharedStatic});
    ts_cfg.members.push_back(cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kSharedStatic});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());
    const auto bound = manager.AddRef(manager.ResolveByName("tls-roots").value(), kClientA);
    ASSERT_FALSE(bound.has_value());
    EXPECT_EQ(bound.error(), Error::kTrustStoreInvalid);
}

// A persisted state that exists but cannot be parsed must not fall back to defaults: that would
// enable members that were disabled.
TEST_F(TrustStoreManagerTest, UnparsablePersistedState_MakesStoreInvalid)
{
    const auto ts_kv = m_dir / "ts_state.kv";
    {
        std::ofstream damaged(ts_kv, std::ios::binary | std::ios::trunc);
        damaged << "this is not a deployment descriptor";
    }

    auto registry = std::make_shared<cert::CertSlotRegistry>();
    static_cast<void>(registry->RegisterSlot(MakeSlotConfig("root-anchor", m_root_slot_kv)));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "tls-roots";
    ts_cfg.deployment_path = ts_kv.string();
    ts_cfg.deployment_format = "kv";
    ts_cfg.members.push_back(cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kSharedStatic});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());
    const auto bound = manager.AddRef(manager.ResolveByName("tls-roots").value(), kClientA);
    ASSERT_FALSE(bound.has_value());
    EXPECT_EQ(bound.error(), Error::kTrustStoreInvalid);
}

TEST_F(TrustStoreManagerTest, MalformedPersistedValue_MakesStoreInvalid)
{
    const auto ts_kv = m_dir / "ts_state.kv";
    storage::DeploymentDescriptor desc;
    desc.Set(std::string{cert::cert_section_names::kTrustStoreState}, "slot.root-anchor.enabled", "maybe");
    ASSERT_TRUE(storage::KvDeploymentWriter{}.Write(ts_kv.string(), desc).has_value());

    auto registry = std::make_shared<cert::CertSlotRegistry>();
    static_cast<void>(registry->RegisterSlot(MakeSlotConfig("root-anchor", m_root_slot_kv)));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "tls-roots";
    ts_cfg.deployment_path = ts_kv.string();
    ts_cfg.deployment_format = "kv";
    ts_cfg.members.push_back(cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kSharedStatic});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());
    const auto bound = manager.AddRef(manager.ResolveByName("tls-roots").value(), kClientA);
    ASSERT_FALSE(bound.has_value());
    EXPECT_EQ(bound.error(), Error::kTrustStoreInvalid);
}

// An absent state file is the first run: the store is valid and members start from the
// configuration.
TEST_F(TrustStoreManagerTest, AbsentPersistedState_IsFirstRunAndStoreIsValid)
{
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    static_cast<void>(registry->RegisterSlot(MakeSlotConfig("root-anchor", m_root_slot_kv)));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "tls-roots";
    ts_cfg.deployment_path = (m_dir / "never_written.kv").string();
    ts_cfg.deployment_format = "kv";
    ts_cfg.members.push_back(cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kSharedStatic});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());
    const auto ts_handle = manager.ResolveByName("tls-roots").value();
    ASSERT_TRUE(manager.AddRef(ts_handle, kClientA).has_value());
    const auto anchors = manager.GetStore(ts_handle)->GetAnchors();
    ASSERT_TRUE(anchors.has_value());
    EXPECT_EQ(anchors->size(), 1U);
}

// A member with no persisted entry (for example one added by a configuration change) starts
// from the configuration, while a persisted disabled member stays disabled.
TEST_F(TrustStoreManagerTest, MemberAbsentFromPersistedState_StartsFromConfiguration)
{
    const auto ts_kv = m_dir / "ts_state.kv";
    storage::DeploymentDescriptor desc;
    desc.Set(std::string{cert::cert_section_names::kTrustStoreState}, "slot.other-anchor.enabled", "false");
    ASSERT_TRUE(storage::KvDeploymentWriter{}.Write(ts_kv.string(), desc).has_value());

    auto registry = std::make_shared<cert::CertSlotRegistry>();
    static_cast<void>(registry->RegisterSlot(MakeSlotConfig("root-anchor", m_root_slot_kv)));
    static_cast<void>(registry->RegisterSlot(MakeSlotConfig("other-anchor", m_root_slot_kv)));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "tls-roots";
    ts_cfg.deployment_path = ts_kv.string();
    ts_cfg.deployment_format = "kv";
    ts_cfg.members.push_back(cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kSharedStatic});
    ts_cfg.members.push_back(cert::TrustStoreMemberConfig{"other-anchor", cert::TrustStoreMemberKind::kSharedStatic});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());
    const auto ts_handle = manager.ResolveByName("tls-roots").value();
    ASSERT_TRUE(manager.AddRef(ts_handle, kClientA).has_value());
    const auto anchors = manager.GetStore(ts_handle)->GetAnchors();
    ASSERT_TRUE(anchors.has_value());
    EXPECT_EQ(anchors->size(), 1U);  // root-anchor enabled by default, other-anchor persisted disabled
}

// ---------------------------------------------------------------------------
// Trust changes are persisted before they are published; reductions apply immediately.
// A directory at the state path makes the atomic write fail while the store is still valid.
// ---------------------------------------------------------------------------

TEST_F(TrustStoreManagerTest, DisableMember_PersistFailure_StillDisablesAndReportsError)
{
    const auto state_path = m_dir / "state_is_a_directory";
    std::filesystem::create_directories(state_path);
    {
        std::ofstream keep(state_path / "keep");  // non-empty, so it can never be replaced or removed
        keep << "x";
    }

    auto registry = std::make_shared<cert::CertSlotRegistry>();
    const auto slot = registry->RegisterSlot(MakeSlotConfig("root-anchor", m_root_slot_kv));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "tls-roots";
    ts_cfg.access_policy.allowed_write_uids = {0U};
    ts_cfg.deployment_path = state_path.string();
    ts_cfg.deployment_format = "kv";
    ts_cfg.members.push_back(cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kSharedStatic});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());
    const auto ts_handle = manager.ResolveByName("tls-roots").value();
    ASSERT_TRUE(manager.AddRef(ts_handle, kClientA).has_value());

    EXPECT_FALSE(manager.DisableMember(ts_handle, slot, kClientA).has_value());

    // The reduction took effect for this run even though it could not be persisted.
    const auto anchors = manager.GetStore(ts_handle)->GetAnchors();
    ASSERT_TRUE(anchors.has_value());
    EXPECT_TRUE(anchors->empty());
}

TEST_F(TrustStoreManagerTest, AddMember_PersistFailure_LeavesNothingTrusted)
{
    const auto state_path = m_dir / "state_is_a_directory";
    std::filesystem::create_directories(state_path);
    {
        std::ofstream keep(state_path / "keep");  // non-empty, so it can never be replaced or removed
        keep << "x";
    }

    auto registry = std::make_shared<cert::CertSlotRegistry>();
    static_cast<void>(registry->RegisterSlot(MakeSlotConfig("empty-anchor", m_empty_slot_kv)));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "mutable-store";
    ts_cfg.access_policy.allowed_write_uids = {0U};
    ts_cfg.deployment_path = state_path.string();
    ts_cfg.deployment_format = "kv";
    ts_cfg.members.push_back(
        cert::TrustStoreMemberConfig{"empty-anchor", cert::TrustStoreMemberKind::kExclusiveMutable});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());
    const auto ts_handle = manager.ResolveByName("mutable-store").value();
    ASSERT_TRUE(manager.AddRef(ts_handle, kClientA).has_value());

    auto cert = ParseCert(m_root_cert);
    ASSERT_NE(cert, nullptr);
    EXPECT_FALSE(manager.AddMember(ts_handle, cert, kClientA).has_value());

    // The error left nothing behind: no cached anchor, and the slot holds no certificate.
    const auto anchors = manager.GetStore(ts_handle)->GetAnchors();
    ASSERT_TRUE(anchors.has_value());
    EXPECT_TRUE(anchors->empty());
    cert::FileBackedSlotHandler fresh_handler{MakeSlotConfig("empty-anchor", m_empty_slot_kv), m_parser};
    const auto state = fresh_handler.GetSlotState();
    ASSERT_TRUE(state.has_value());
    EXPECT_EQ(state.value(), score::crypto::CertificateSlotState::kEmpty);
}

// ---------------------------------------------------------------------------
// AddMember — a failed CRL write is reported and never leaves a trusted anchor behind.
// A directory at the CRL path makes the CRL write fail.
// ---------------------------------------------------------------------------

TEST_F(TrustStoreManagerTest, AddMember_NewMember_CrlWriteFailure_ReturnsErrorAndLeavesSlotEmpty)
{
    const auto cert_path = m_dir / "excl.pem";
    const auto crl_path = m_dir / "crl_is_a_directory";
    std::filesystem::create_directories(crl_path);
    {
        std::ofstream keep(crl_path / "keep");  // non-empty, so it can never be replaced or removed
        keep << "x";
    }
    const auto kv = m_dir / "excl.kv";
    storage::DeploymentDescriptor desc;
    desc.Set("certificate", "cert_path", cert_path.string());
    desc.Set("certificate", "cert_format", "pem");
    desc.Set("crl", "crl_path", crl_path.string());
    ASSERT_TRUE(storage::KvDeploymentWriter{}.Write(kv.string(), desc).has_value());

    auto registry = std::make_shared<cert::CertSlotRegistry>();
    static_cast<void>(registry->RegisterSlot(MakeSlotConfig("excl-anchor", kv)));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "mutable-store";
    ts_cfg.access_policy.allowed_write_uids = {0U};
    ts_cfg.members.push_back(
        cert::TrustStoreMemberConfig{"excl-anchor", cert::TrustStoreMemberKind::kExclusiveMutable});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());
    const auto ts_handle = manager.ResolveByName("mutable-store").value();

    auto cert = ParseCert(m_root_cert);
    ASSERT_NE(cert, nullptr);
    const std::vector<std::uint8_t> crl_bytes{0xC0U, 0xC1U};
    const auto crl = std::make_shared<const cert::CrlData>(cert::CrlData{crl_bytes, score::crypto::FormatType::kDer});
    EXPECT_FALSE(manager.AddMember(ts_handle, cert, kClientA, crl).has_value());

    cert::FileBackedSlotHandler fresh_handler{MakeSlotConfig("excl-anchor", kv), m_parser};
    const auto state = fresh_handler.GetSlotState();
    ASSERT_TRUE(state.has_value());
    EXPECT_EQ(state.value(), score::crypto::CertificateSlotState::kEmpty);
    const auto anchors = manager.GetStore(ts_handle)->GetAnchors();
    ASSERT_TRUE(anchors.has_value());
    EXPECT_TRUE(anchors->empty());
}

TEST_F(TrustStoreManagerTest, AddMember_ExistingMember_CrlWriteFailure_ReturnsError)
{
    const auto cert_path = m_dir / "excl.pem";
    const auto crl_path = m_dir / "crl_is_a_directory";
    std::filesystem::create_directories(crl_path);
    {
        std::ofstream keep(crl_path / "keep");  // non-empty, so it can never be replaced or removed
        keep << "x";
    }
    const auto kv = m_dir / "excl.kv";
    storage::DeploymentDescriptor desc;
    desc.Set("certificate", "cert_path", cert_path.string());
    desc.Set("certificate", "cert_format", "pem");
    desc.Set("crl", "crl_path", crl_path.string());
    ASSERT_TRUE(storage::KvDeploymentWriter{}.Write(kv.string(), desc).has_value());

    auto registry = std::make_shared<cert::CertSlotRegistry>();
    static_cast<void>(registry->RegisterSlot(MakeSlotConfig("excl-anchor", kv)));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "mutable-store";
    ts_cfg.access_policy.allowed_write_uids = {0U};
    ts_cfg.members.push_back(
        cert::TrustStoreMemberConfig{"excl-anchor", cert::TrustStoreMemberKind::kExclusiveMutable});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());
    const auto ts_handle = manager.ResolveByName("mutable-store").value();

    auto cert = ParseCert(m_root_cert);
    ASSERT_NE(cert, nullptr);
    ASSERT_TRUE(manager.AddMember(ts_handle, cert, kClientA).has_value());

    const std::vector<std::uint8_t> crl_bytes{0xC0U, 0xC1U};
    const auto crl = std::make_shared<const cert::CrlData>(cert::CrlData{crl_bytes, score::crypto::FormatType::kDer});
    // The certificate is already a member, so the call is an upsert of its CRL; that failure is reported.
    EXPECT_FALSE(manager.AddMember(ts_handle, cert, kClientA, crl).has_value());
}

// ---------------------------------------------------------------------------
// DisableMember / EnableMember — anchor visibility toggles synchronously.
// Default-deny write policy: allowed_write_uids must contain caller UID.
// kClientA = 1U → GetUidFromClientId = upper 32 bits = 0.
// ---------------------------------------------------------------------------

TEST_F(TrustStoreManagerTest, DisableAndReEnable_MemberTogglesAnchorVisibility)
{
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    const auto slot = registry->RegisterSlot(StaticSlotConfig("root-anchor"));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "tls-roots";
    ts_cfg.access_policy.allowed_write_uids = {0U};
    ts_cfg.members.push_back(cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kSharedStatic});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());

    const auto ts_handle = manager.ResolveByName("tls-roots").value();
    auto store = manager.GetStore(ts_handle);
    ASSERT_NE(store, nullptr);

    // Initial load: one anchor present.
    auto initial = store->GetAnchors();
    ASSERT_TRUE(initial.has_value());
    ASSERT_EQ(initial->size(), 1U);
    EXPECT_EQ((*initial)[0]->GetSubject(), kSubjectInitial);

    // Disable: anchor must disappear from the store immediately.
    ASSERT_TRUE(manager.DisableMember(ts_handle, slot, kClientA).has_value());
    auto after_disable = store->GetAnchors();
    ASSERT_TRUE(after_disable.has_value());
    EXPECT_EQ(after_disable->size(), 0U);

    // Re-enable: anchor must reappear with the same subject.
    ASSERT_TRUE(manager.EnableMember(ts_handle, slot, kClientA).has_value());
    auto after_enable = store->GetAnchors();
    ASSERT_TRUE(after_enable.has_value());
    ASSERT_EQ(after_enable->size(), 1U);
    EXPECT_EQ((*after_enable)[0]->GetSubject(), kSubjectInitial);
}

// ---------------------------------------------------------------------------
// Two trust stores sharing one cert slot — both get the same CertObject
// instance from the shared weak-ptr cache, and the slot is loaded from disk
// exactly once.
// ---------------------------------------------------------------------------

TEST_F(TrustStoreManagerTest, TwoStores_OneSlot_BothGetMemberships)
{
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    const auto slot = registry->RegisterSlot(StaticSlotConfig("shared-anchor"));

    cert::TrustStoreConfig store_a;
    store_a.store_name = "store-a";
    store_a.members.push_back(cert::TrustStoreMemberConfig{"shared-anchor", cert::TrustStoreMemberKind::kSharedStatic});

    cert::TrustStoreConfig store_b;
    store_b.store_name = "store-b";
    store_b.members.push_back(cert::TrustStoreMemberConfig{"shared-anchor", cert::TrustStoreMemberKind::kSharedStatic});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({store_a, store_b}, registry, MakeSlotManager(registry)).has_value());

    // Both stores report membership for the shared slot.
    EXPECT_EQ(manager.GetMembershipsForSlot(slot).size(), 2U);

    const auto ts_handle_a = manager.ResolveByName("store-a").value();
    const auto ts_handle_b = manager.ResolveByName("store-b").value();
    auto anchors_a = manager.GetStore(ts_handle_a)->GetAnchors();
    auto anchors_b = manager.GetStore(ts_handle_b)->GetAnchors();
    ASSERT_TRUE(anchors_a.has_value());
    ASSERT_TRUE(anchors_b.has_value());
    ASSERT_EQ(anchors_a->size(), 1U);
    ASSERT_EQ(anchors_b->size(), 1U);

    // Shared weak-ptr cache: both stores return the same CertObject pointer.
    EXPECT_EQ((*anchors_a)[0].get(), (*anchors_b)[0].get());
    EXPECT_EQ((*anchors_a)[0]->GetSubject(), kSubjectInitial);
}

// ---------------------------------------------------------------------------
// AddMember — stores a parsed cert into an empty exclusive slot and immediately
// makes it visible as a trust anchor. Persistence is verified by loading with
// a fresh FileBackedSlotHandler after AddMember completes.
// ---------------------------------------------------------------------------

TEST_F(TrustStoreManagerTest, AddMember_ToExclusiveSlot_AddsAnchorAndPersistsToDisk)
{
    RecordProperty("PartiallyVerifies",
                   "comp_req__crypto_cert_mgmt__trust_stores, comp_req__crypto_cert_management__persistence");
    RecordProperty(
        "Description",
        "Adds a certificate to an exclusive trust-store slot, exposes it as an anchor, and reloads it from disk.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    auto registry = std::make_shared<cert::CertSlotRegistry>();
    static_cast<void>(registry->RegisterSlot(MakeSlotConfig("empty-anchor", m_empty_slot_kv)));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "mutable-store";
    ts_cfg.access_policy.allowed_write_uids = {0U};
    ts_cfg.members.push_back(
        cert::TrustStoreMemberConfig{"empty-anchor", cert::TrustStoreMemberKind::kExclusiveMutable});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());

    const auto ts_handle = manager.ResolveByName("mutable-store").value();
    auto store = manager.GetStore(ts_handle);
    ASSERT_NE(store, nullptr);

    // Slot is empty — no anchors before AddMember.
    auto before = store->GetAnchors();
    ASSERT_TRUE(before.has_value());
    EXPECT_EQ(before->size(), 0U);

    // Parse the test vector cert to get a real CertObject to add.
    auto cert = ParseCert(m_root_cert);
    ASSERT_NE(cert, nullptr);
    EXPECT_EQ(cert->GetSubject(), kSubjectInitial);

    ASSERT_TRUE(manager.AddMember(ts_handle, cert, kClientA).has_value());

    // Anchor must be visible immediately after AddMember.
    auto after = store->GetAnchors();
    ASSERT_TRUE(after.has_value());
    ASSERT_EQ(after->size(), 1U);
    EXPECT_EQ((*after)[0]->GetSubject(), kSubjectInitial);

    // Verify persistence: a fresh handler must read the cert from disk.
    const auto empty_cfg = MakeSlotConfig("empty-anchor", m_empty_slot_kv);
    cert::FileBackedSlotHandler fresh_handler{empty_cfg, m_parser};
    auto persisted = fresh_handler.LoadCertificate();
    ASSERT_TRUE(persisted.has_value());
    EXPECT_EQ((*persisted)->GetSubject(), kSubjectInitial);
}

// ---------------------------------------------------------------------------
// RemoveMember — finds the anchor by its real SHA-256 fingerprint, clears the
// slot, and removes it from the in-memory anchor set.
// ---------------------------------------------------------------------------

TEST_F(TrustStoreManagerTest, RemoveMember_ByFingerprint_RemovesAnchor)
{
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    static_cast<void>(registry->RegisterSlot(MakeSlotConfig("root-anchor", m_root_slot_kv)));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "mutable-store";
    ts_cfg.access_policy.allowed_write_uids = {0U};
    ts_cfg.members.push_back(
        cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kExclusiveMutable});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());

    const auto ts_handle = manager.ResolveByName("mutable-store").value();
    auto store = manager.GetStore(ts_handle);
    ASSERT_NE(store, nullptr);

    // Load the anchors to obtain the real SHA-256 fingerprint.
    auto before = store->GetAnchors();
    ASSERT_TRUE(before.has_value());
    ASSERT_EQ(before->size(), 1U);
    EXPECT_EQ((*before)[0]->GetSubject(), kSubjectInitial);

    const auto fp_span = (*before)[0]->GetFingerprint();
    ASSERT_EQ(fp_span.size(), 32U);
    const std::vector<std::uint8_t> fingerprint{fp_span.begin(), fp_span.end()};

    ASSERT_TRUE(manager.RemoveMember(ts_handle, fingerprint, kClientA).has_value());

    // Anchor must be gone after removal.
    auto after = store->GetAnchors();
    ASSERT_TRUE(after.has_value());
    EXPECT_EQ(after->size(), 0U);
}

// ---------------------------------------------------------------------------
// AcknowledgeMemberUpdate — re-enables a disabled member slot, triggers a
// fresh LoadCertificate from disk, and records the accepted fingerprint.
// ---------------------------------------------------------------------------

TEST_F(TrustStoreManagerTest, AcknowledgeMemberUpdate_TransitionsDisabledMemberToEnabled)
{
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    const auto slot = registry->RegisterSlot(MakeSlotConfig("root-anchor", m_root_slot_kv));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "cond-store";
    ts_cfg.access_policy.allowed_write_uids = {0U};
    ts_cfg.conditional_slot_initialization = cert::ConditionalSlotInitialization::kEnableAndAcceptCurrent;
    ts_cfg.members.push_back(
        cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kConditionalExternal});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());

    const auto ts_handle = manager.ResolveByName("cond-store").value();
    auto store = manager.GetStore(ts_handle);
    ASSERT_NE(store, nullptr);

    // Initial load — anchor present.
    auto initial = store->GetAnchors();
    ASSERT_TRUE(initial.has_value());
    ASSERT_EQ(initial->size(), 1U);
    EXPECT_EQ((*initial)[0]->GetSubject(), kSubjectInitial);

    ASSERT_TRUE(manager.DisableMember(ts_handle, slot, kClientA).has_value());
    ASSERT_TRUE(manager.EnableMember(ts_handle, slot, kClientA).has_value());
    ASSERT_TRUE(manager.DisableMember(ts_handle, slot, kClientA).has_value());

    // Rotate cert on disk so that AcknowledgeMemberUpdate reloads a different cert.
    ASSERT_TRUE(std::filesystem::copy_file("score/tests/test_vectors/certificate/basic/certificate_updated.pem",
                                           m_root_cert,
                                           std::filesystem::copy_options::overwrite_existing));

    // Disable — simulates detection of an unexpected content change.
    ASSERT_TRUE(manager.DisableMember(ts_handle, slot, kClientA).has_value());
    {
        auto after_disable = store->GetAnchors();
        ASSERT_TRUE(after_disable.has_value());
        EXPECT_EQ(after_disable->size(), 0U);
    }

    // A stale caller snapshot cannot acknowledge newly changed slot content.
    const auto stale_snapshot = manager.GetMemberSnapshot(ts_handle, slot);
    ASSERT_TRUE(stale_snapshot.has_value());
    EXPECT_EQ(stale_snapshot->status, score::crypto::MemberStatus::kFingerprintMismatch);
    const auto updated_cert = ParseCert("score/tests/test_vectors/certificate/basic/certificate_updated.pem");
    ASSERT_NE(updated_cert, nullptr);
    const auto updated_fingerprint = updated_cert->GetFingerprint();
    const std::vector<std::uint8_t> snapshot_fingerprint(stale_snapshot->fingerprint.begin(),
                                                         stale_snapshot->fingerprint.end());
    const std::vector<std::uint8_t> expected_snapshot_fingerprint(updated_fingerprint.begin(),
                                                                  updated_fingerprint.end());
    EXPECT_EQ(snapshot_fingerprint, expected_snapshot_fingerprint);

    const auto original_cert = ParseCert("score/tests/test_vectors/certificate/basic/certificate.pem");
    ASSERT_NE(original_cert, nullptr);
    const auto original_fingerprint = original_cert->GetFingerprint();
    const auto malformed_ack = manager.AcknowledgeMemberUpdate(
        ts_handle, slot, score::crypto::span<const std::uint8_t>{original_fingerprint.data(), 0U}, kClientA);
    ASSERT_FALSE(malformed_ack.has_value());
    EXPECT_EQ(malformed_ack.error(), score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);

    const auto enable_before_ack = manager.EnableMember(ts_handle, slot, kClientA);
    ASSERT_FALSE(enable_before_ack.has_value());
    EXPECT_EQ(enable_before_ack.error(), score::crypto::daemon::common::DaemonErrorCode::kInvalidOperation);

    const auto stale_ack = manager.AcknowledgeMemberUpdate(
        ts_handle,
        slot,
        score::crypto::span<const std::uint8_t>{original_fingerprint.data(), original_fingerprint.size()},
        kClientA);
    ASSERT_FALSE(stale_ack.has_value());
    EXPECT_EQ(stale_ack.error(), score::crypto::daemon::common::DaemonErrorCode::kInvalidOperation);

    // Acknowledge — fresh load matches the inspected fingerprint, records it, and re-enables.
    ASSERT_TRUE(manager
                    .AcknowledgeMemberUpdate(
                        ts_handle,
                        slot,
                        score::crypto::span<const std::uint8_t>{updated_fingerprint.data(), updated_fingerprint.size()},
                        kClientA)
                    .has_value());

    auto after_ack = store->GetAnchors();
    ASSERT_TRUE(after_ack.has_value());
    ASSERT_EQ(after_ack->size(), 1U);
    // AcknowledgeMemberUpdate reloaded from disk — must now show the rotated cert.
    EXPECT_EQ((*after_ack)[0]->GetSubject(), kSubjectUpdated);
    EXPECT_EQ((*after_ack)[0]->GetFingerprint().size(), score::crypto::kSha256FingerprintSize);
}

TEST_F(TrustStoreManagerTest, EnableConditionalMemberWithoutAcceptedFingerprintIsRejected)
{
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    const auto slot = registry->RegisterSlot(MakeSlotConfig("root-anchor", m_root_slot_kv));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "cond-store";
    ts_cfg.access_policy.allowed_write_uids = {0U};
    ts_cfg.conditional_slot_initialization = cert::ConditionalSlotInitialization::kDisableUntilAccepted;
    ts_cfg.members.push_back(
        cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kConditionalExternal});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());
    const auto ts_handle = manager.ResolveByName("cond-store").value();
    auto store = manager.GetStore(ts_handle);
    ASSERT_NE(store, nullptr);

    const auto anchors = store->GetAnchors();
    ASSERT_TRUE(anchors.has_value());
    EXPECT_TRUE(anchors->empty());
    const auto before = manager.GetMemberSnapshot(ts_handle, slot);
    ASSERT_TRUE(before.has_value());
    EXPECT_EQ(before->status, score::crypto::MemberStatus::kAwaitingAcknowledgement);

    const auto result = manager.EnableMember(ts_handle, slot, kClientA);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kInvalidOperation);

    const auto after = manager.GetMemberSnapshot(ts_handle, slot);
    ASSERT_TRUE(after.has_value());
    EXPECT_EQ(after->status, score::crypto::MemberStatus::kAwaitingAcknowledgement);
    const auto anchors_after = store->GetAnchors();
    ASSERT_TRUE(anchors_after.has_value());
    EXPECT_TRUE(anchors_after->empty());
}

// ---------------------------------------------------------------------------
// ConditionalExternal members require acknowledgment after a slot update.
//
// Steps:
//  1. kConditionalExternal member with kEnableAndAcceptCurrent init policy:
//     first GetAnchors() records accepted_fingerprint = fingerprint(cert A).
//  2. Cert B is written to the slot and NotifySlotChanged() is called.
//  3. The member is disabled immediately → GetAnchors() returns no anchors.
//  4. AcknowledgeMemberUpdate → fresh load of cert B, records the new
//     fingerprint, and re-enables the member.
//  5. GetAnchors() returns cert B without another reload cycle.
// ---------------------------------------------------------------------------

TEST_F(TrustStoreManagerTest, ConditionalExternal_FingerprintMismatch_AutoDisablesUntilAcknowledged)
{
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    auto slot_config = MakeSlotConfig("root-anchor", m_root_slot_kv);
    slot_config.access_policy.allowed_uids = {0U};
    slot_config.access_policy.allowed_write_uids = {0U};
    const auto slot = registry->RegisterSlot(slot_config);

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "cond-store";
    ts_cfg.access_policy.allowed_write_uids = {0U};
    ts_cfg.conditional_slot_initialization = cert::ConditionalSlotInitialization::kEnableAndAcceptCurrent;
    ts_cfg.members.push_back(
        cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kConditionalExternal});

    auto slot_manager = MakeSlotManager(registry);
    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, slot_manager).has_value());

    const auto ts_handle = manager.ResolveByName("cond-store").value();
    auto store = manager.GetStore(ts_handle);
    ASSERT_NE(store, nullptr);

    // Step 1: Initial load — kEnableAndAcceptCurrent records accepted_fingerprint.
    // The ref is established before the load so that ReleaseRef later triggers eviction.
    ASSERT_TRUE(manager.AddRef(ts_handle, kClientA).has_value());
    {
        auto initial = store->GetAnchors();
        ASSERT_TRUE(initial.has_value());
        ASSERT_EQ(initial->size(), 1U);
        EXPECT_EQ((*initial)[0]->GetSubject(), kSubjectInitial);
        // 'initial' drops here; the only remaining strong ref is inside TrustStoreHandler::m_slots.
    }

    // Step 2: Update the member slot through the certificate-slot write path.
    const auto updated = ParseCert("score/tests/test_vectors/certificate/basic/certificate_updated.pem");
    ASSERT_NE(updated, nullptr);
    ASSERT_TRUE(slot_manager->StoreCertificate(slot, kClientA, *updated).has_value());
    manager.NotifySlotChanged(slot);

    // Step 3: The direct slot update disables the conditional member until it is acknowledged.
    {
        auto after_update = store->GetAnchors();
        ASSERT_TRUE(after_update.has_value());
        EXPECT_EQ(after_update->size(), 0U);
    }

    // Step 4: Acknowledge the update and load the replacement certificate.
    const auto updated_fingerprint = updated->GetFingerprint();
    ASSERT_TRUE(manager
                    .AcknowledgeMemberUpdate(
                        ts_handle,
                        slot,
                        score::crypto::span<const std::uint8_t>{updated_fingerprint.data(), updated_fingerprint.size()},
                        kClientA)
                    .has_value());

    // Step 5: GetAnchors() returns cert B: the member is enabled again and resolves to the
    // replacement certificate that AcknowledgeMemberUpdate accepted.
    auto after_ack = store->GetAnchors();
    ASSERT_TRUE(after_ack.has_value());
    ASSERT_EQ(after_ack->size(), 1U);
    EXPECT_EQ((*after_ack)[0]->GetSubject(), kSubjectUpdated);
    EXPECT_EQ((*after_ack)[0]->GetFingerprint().size(), score::crypto::kSha256FingerprintSize);
}

// ---------------------------------------------------------------------------
// AddMember — CRL propagation: non-empty crl_bytes are stored to the exclusive
// slot alongside the certificate.
// ---------------------------------------------------------------------------

TEST_F(TrustStoreManagerTest, AddMember_WithCrlBytes_StoresAndPersistsCrl)
{
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    static_cast<void>(registry->RegisterSlot(MakeSlotConfig("empty-anchor", m_empty_slot_kv)));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "mutable-store";
    ts_cfg.access_policy.allowed_write_uids = {0U};
    ts_cfg.members.push_back(
        cert::TrustStoreMemberConfig{"empty-anchor", cert::TrustStoreMemberKind::kExclusiveMutable});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());

    const auto ts_handle = manager.ResolveByName("mutable-store").value();

    auto cert = ParseCert(m_root_cert);
    ASSERT_NE(cert, nullptr);

    const std::vector<std::uint8_t> crl{0xC0U, 0xC1U, 0xC2U};
    const auto crl_ptr = std::make_shared<const cert::CrlData>(cert::CrlData{crl, score::crypto::FormatType::kDer});

    ASSERT_TRUE(manager.AddMember(ts_handle, cert, kClientA, crl_ptr).has_value());

    // Verify via a fresh handler: cert and CRL are both on disk.
    const auto cfg = MakeSlotConfig("empty-anchor", m_empty_slot_kv);
    cert::FileBackedSlotHandler fresh_handler{cfg, m_parser};
    ASSERT_TRUE(fresh_handler.LoadCertificate().has_value());
    ASSERT_TRUE(fresh_handler.HasCrl().has_value());
    ASSERT_TRUE(fresh_handler.HasCrl().value());
    const auto loaded_crl = fresh_handler.LoadCrlData();
    ASSERT_TRUE(loaded_crl.has_value());
    ASSERT_TRUE(loaded_crl->has_value());
    EXPECT_EQ((*loaded_crl)->bytes, crl);
    EXPECT_EQ((*loaded_crl)->format, score::crypto::FormatType::kDer);
}

// ---------------------------------------------------------------------------
// AddMember — upsert semantics: if the cert is already an exclusive member and
// crl_bytes is non-empty, the CRL is stored/updated without re-adding the cert.
// ---------------------------------------------------------------------------

TEST_F(TrustStoreManagerTest, AddMember_ExistingExclusiveMember_UpsertsCrl)
{
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    static_cast<void>(registry->RegisterSlot(MakeSlotConfig("empty-anchor", m_empty_slot_kv)));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "mutable-store";
    ts_cfg.access_policy.allowed_write_uids = {0U};
    ts_cfg.members.push_back(
        cert::TrustStoreMemberConfig{"empty-anchor", cert::TrustStoreMemberKind::kExclusiveMutable});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());

    const auto ts_handle = manager.ResolveByName("mutable-store").value();

    auto cert = ParseCert(m_root_cert);
    ASSERT_NE(cert, nullptr);

    // First add: cert only, no CRL.
    ASSERT_TRUE(manager.AddMember(ts_handle, cert, kClientA).has_value());
    {
        const auto cfg = MakeSlotConfig("empty-anchor", m_empty_slot_kv);
        cert::FileBackedSlotHandler fh{cfg, m_parser};
        ASSERT_TRUE(fh.HasCrl().has_value());
        EXPECT_FALSE(fh.HasCrl().value());
    }

    // Second add: same cert, with CRL — upsert path.
    const std::vector<std::uint8_t> crl{0xAAU, 0xBBU, 0xCCU};
    const auto crl_ptr = std::make_shared<const cert::CrlData>(cert::CrlData{crl, score::crypto::FormatType::kDer});
    ASSERT_TRUE(manager.AddMember(ts_handle, cert, kClientA, crl_ptr).has_value());

    const auto cfg = MakeSlotConfig("empty-anchor", m_empty_slot_kv);
    cert::FileBackedSlotHandler fresh_handler{cfg, m_parser};
    ASSERT_TRUE(fresh_handler.HasCrl().has_value());
    ASSERT_TRUE(fresh_handler.HasCrl().value());
    const auto loaded_crl = fresh_handler.LoadCrlData();
    ASSERT_TRUE(loaded_crl.has_value());
    ASSERT_TRUE(loaded_crl->has_value());
    EXPECT_EQ((*loaded_crl)->bytes, crl);
}

// ---------------------------------------------------------------------------
// AddMember — dedup: cert already present as a shared-static member with CRL
// bytes supplied → kUnsupportedOperation (trust store does not own shared slots).
// ---------------------------------------------------------------------------

TEST_F(TrustStoreManagerTest, AddMember_SharedStaticMember_WithCrl_ReturnsUnsupportedOperation)
{
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    static_cast<void>(registry->RegisterSlot(MakeSlotConfig("root-anchor", m_root_slot_kv)));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "mixed-store";
    ts_cfg.access_policy.allowed_write_uids = {0U};
    ts_cfg.members.push_back(cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kSharedStatic});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());

    const auto ts_handle = manager.ResolveByName("mixed-store").value();

    // Parse the same cert that is already the shared-static member.
    auto cert = ParseCert(m_root_cert);
    ASSERT_NE(cert, nullptr);

    const std::vector<std::uint8_t> crl{0x01U, 0x02U};
    const auto crl_ptr = std::make_shared<const cert::CrlData>(cert::CrlData{crl, score::crypto::FormatType::kDer});

    const auto result = manager.AddMember(ts_handle, cert, kClientA, crl_ptr);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
}

// ---------------------------------------------------------------------------
// AddMember — dedup covers ALL member types: cert already in shared-static slot
// is found before exclusive slots are searched; no exclusive slot is consumed.
// ---------------------------------------------------------------------------

TEST_F(TrustStoreManagerTest, AddMember_DeduplicationChecksAllMemberTypes)
{
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    static_cast<void>(registry->RegisterSlot(MakeSlotConfig("root-anchor", m_root_slot_kv)));
    static_cast<void>(registry->RegisterSlot(MakeSlotConfig("empty-anchor", m_empty_slot_kv)));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "mixed-store";
    ts_cfg.access_policy.allowed_write_uids = {0U};
    ts_cfg.members.push_back(cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kSharedStatic});
    ts_cfg.members.push_back(
        cert::TrustStoreMemberConfig{"empty-anchor", cert::TrustStoreMemberKind::kExclusiveMutable});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());

    const auto ts_handle = manager.ResolveByName("mixed-store").value();

    // Parse the same cert that is already the shared-static member.
    auto cert = ParseCert(m_root_cert);
    ASSERT_NE(cert, nullptr);

    // AddMember without CRL: dedup on shared-static → idempotent success.
    ASSERT_TRUE(manager.AddMember(ts_handle, cert, kClientA).has_value());

    // The exclusive slot must still be empty — not consumed by AddMember.
    const auto exclusive_cfg = MakeSlotConfig("empty-anchor", m_empty_slot_kv);
    cert::FileBackedSlotHandler fresh_handler{exclusive_cfg, m_parser};
    const auto state = fresh_handler.GetSlotState();
    ASSERT_TRUE(state.has_value());
    EXPECT_EQ(*state, score::crypto::CertificateSlotState::kEmpty);
}

// ---------------------------------------------------------------------------
// StoreCrlForMember — writes CRL to the exclusive slot holding the given cert.
// ---------------------------------------------------------------------------

TEST_F(TrustStoreManagerTest, StoreCrlForMember_WritesToExclusiveSlot)
{
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    const auto slot_handle = registry->RegisterSlot(MakeSlotConfig("empty-anchor", m_empty_slot_kv));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "mutable-store";
    ts_cfg.access_policy.allowed_write_uids = {0U};
    ts_cfg.members.push_back(
        cert::TrustStoreMemberConfig{"empty-anchor", cert::TrustStoreMemberKind::kExclusiveMutable});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());

    const auto ts_handle = manager.ResolveByName("mutable-store").value();

    auto cert = ParseCert(m_root_cert);
    ASSERT_NE(cert, nullptr);

    // First add the cert without CRL.
    ASSERT_TRUE(manager.AddMember(ts_handle, cert, kClientA).has_value());

    // Now import a CRL for that member by slot handle.
    const std::vector<std::uint8_t> crl{0xD0U, 0xD1U, 0xD2U};
    const cert::CrlData crl_data{crl, score::crypto::FormatType::kDer};

    ASSERT_TRUE(manager.StoreCrlForMember(ts_handle, slot_handle, crl_data, kClientA).has_value());

    // Verify persistence: fresh handler must read the CRL.
    const auto cfg = MakeSlotConfig("empty-anchor", m_empty_slot_kv);
    cert::FileBackedSlotHandler fresh_handler{cfg, m_parser};
    ASSERT_TRUE(fresh_handler.HasCrl().has_value());
    ASSERT_TRUE(fresh_handler.HasCrl().value());
    const auto loaded_crl = fresh_handler.LoadCrlData();
    ASSERT_TRUE(loaded_crl.has_value());
    ASSERT_TRUE(loaded_crl->has_value());
    EXPECT_EQ((*loaded_crl)->bytes, crl);
}

// A CRL written to an exclusive slot through the trust store must be visible through
// CertSlotManager's cached CRL state, which a write through the backend handler does not
// invalidate on its own.
TEST_F(TrustStoreManagerTest, ExclusiveMemberCrlWrites_AreVisibleThroughSlotManagerCache)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_mgmt__tstr_cnsstncy");
    RecordProperty("Description",
                   "CRL import and delete on an exclusive trust-store member are reflected by the slot manager's "
                   "CRL queries after its CRL state was cached.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    auto registry = std::make_shared<cert::CertSlotRegistry>();
    const auto slot_handle = registry->RegisterSlot(MakeSlotConfig("empty-anchor", m_empty_slot_kv));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "mutable-store";
    ts_cfg.access_policy.allowed_write_uids = {0U};
    ts_cfg.members.push_back(
        cert::TrustStoreMemberConfig{"empty-anchor", cert::TrustStoreMemberKind::kExclusiveMutable});

    auto slot_manager = MakeSlotManager(registry);
    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, slot_manager).has_value());
    const auto ts_handle = manager.ResolveByName("mutable-store").value();

    const auto cert = ParseCert(m_root_cert);
    ASSERT_NE(cert, nullptr);
    ASSERT_TRUE(manager.AddMember(ts_handle, cert, kClientA).has_value());

    // Populate the slot manager's CRL cache with the "no CRL" answer.
    const auto before = slot_manager->HasCrl(slot_handle, kClientA);
    ASSERT_TRUE(before.has_value());
    EXPECT_FALSE(*before);

    const std::vector<std::uint8_t> crl{0xD0U, 0xD1U, 0xD2U};
    const cert::CrlData crl_data{crl, score::crypto::FormatType::kDer};
    ASSERT_TRUE(manager.StoreCrlForMember(ts_handle, slot_handle, crl_data, kClientA).has_value());
    const auto after_import = slot_manager->HasCrl(slot_handle, kClientA);
    ASSERT_TRUE(after_import.has_value());
    EXPECT_TRUE(*after_import);

    ASSERT_TRUE(manager.ClearCrlForMember(ts_handle, slot_handle, kClientA).has_value());
    const auto after_delete = slot_manager->HasCrl(slot_handle, kClientA);
    ASSERT_TRUE(after_delete.has_value());
    EXPECT_FALSE(*after_delete);
}

TEST_F(TrustStoreManagerTest, StoreCrlForMember_DeniesUnauthorizedWriter)
{
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    const auto slot_handle = registry->RegisterSlot(MakeSlotConfig("empty-anchor", m_empty_slot_kv));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "mutable-store";
    ts_cfg.access_policy.allowed_write_uids = {0U};
    ts_cfg.members.push_back(
        cert::TrustStoreMemberConfig{"empty-anchor", cert::TrustStoreMemberKind::kExclusiveMutable});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());
    const auto ts_handle = manager.ResolveByName("mutable-store").value();

    auto cert = ParseCert(m_root_cert);
    ASSERT_NE(cert, nullptr);
    ASSERT_TRUE(manager.AddMember(ts_handle, cert, kClientA).has_value());

    const std::vector<std::uint8_t> crl{0xD0U, 0xD1U, 0xD2U};
    const cert::CrlData crl_data{crl, score::crypto::FormatType::kDer};
    const auto unauthorized = static_cast<dm::ClientId>(1ULL << 32U) | 3U;
    const auto result = manager.StoreCrlForMember(ts_handle, slot_handle, crl_data, unauthorized);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kAccessDenied);
}

// ---------------------------------------------------------------------------
// AddMember — capacity exceeded: all exclusive slots are occupied by a
// different cert. The trust store has no shared-static member and no empty
// exclusive slot.
// ---------------------------------------------------------------------------

TEST_F(TrustStoreManagerTest, AddMember_NoEmptyExclusiveSlot_ReturnsCapacityExceeded)
{
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    static_cast<void>(registry->RegisterSlot(MakeSlotConfig("root-anchor", m_root_slot_kv)));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "full-store";
    ts_cfg.access_policy.allowed_write_uids = {0U};
    ts_cfg.members.push_back(
        cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kExclusiveMutable});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());

    const auto ts_handle = manager.ResolveByName("full-store").value();

    // root-anchor already holds a cert (kSubjectInitial). Add the same cert first to fill the slot.
    auto cert_a = ParseCert(m_root_cert);
    ASSERT_NE(cert_a, nullptr);
    ASSERT_TRUE(manager.AddMember(ts_handle, cert_a, kClientA).has_value());

    // Now try to add a *different* cert — slot is occupied, no empty exclusive slot.
    // Use the updated cert (different fingerprint) to bypass dedup.
    ASSERT_TRUE(std::filesystem::copy_file("score/tests/test_vectors/certificate/basic/certificate_updated.pem",
                                           m_dir / "alt.pem",
                                           std::filesystem::copy_options::overwrite_existing));
    auto cert_b = ParseCert(m_dir / "alt.pem");
    ASSERT_NE(cert_b, nullptr);

    const auto result = manager.AddMember(ts_handle, cert_b, kClientA);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kTrustStoreCapacityExceeded);
}

// ---------------------------------------------------------------------------
// RemoveMember — wrong fingerprint: no exclusive member matches; returns
// kInvalidArgument rather than silently succeeding.
// ---------------------------------------------------------------------------

TEST_F(TrustStoreManagerTest, RemoveMember_WrongFingerprint_ReturnsInvalidArgument)
{
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    static_cast<void>(registry->RegisterSlot(MakeSlotConfig("root-anchor", m_root_slot_kv)));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "mutable-store";
    ts_cfg.access_policy.allowed_write_uids = {0U};
    ts_cfg.members.push_back(
        cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kExclusiveMutable});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());

    const auto ts_handle = manager.ResolveByName("mutable-store").value();

    const std::vector<std::uint8_t> wrong_fp(32U, 0xFFU);
    const auto result = manager.RemoveMember(ts_handle, wrong_fp, kClientA);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
}

// ---------------------------------------------------------------------------
// StoreCrlForMember — returns kUnsupportedOperation when the target slot is
// a shared-static member (the trust store does not own it).
// ---------------------------------------------------------------------------

TEST_F(TrustStoreManagerTest, StoreCrlForMember_SharedStaticSlot_ReturnsUnsupportedOperation)
{
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    const auto slot_handle = registry->RegisterSlot(MakeSlotConfig("root-anchor", m_root_slot_kv));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "shared-store";
    ts_cfg.access_policy.allowed_write_uids = {0U};
    ts_cfg.members.push_back(cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kSharedStatic});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());

    const auto ts_handle = manager.ResolveByName("shared-store").value();

    const std::vector<std::uint8_t> crl{0x01U, 0x02U, 0x03U};
    const cert::CrlData crl_data{crl, score::crypto::FormatType::kDer};

    const auto result = manager.StoreCrlForMember(ts_handle, slot_handle, crl_data, kClientA);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
}

// ---------------------------------------------------------------------------
// EnableMember / DisableMember — slot is not a registered member of the trust
// store; returns kInvalidArgument.
// ---------------------------------------------------------------------------

TEST_F(TrustStoreManagerTest, EnableMember_UnregisteredSlot_ReturnsInvalidArgument)
{
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    static_cast<void>(registry->RegisterSlot(StaticSlotConfig("root-anchor")));
    // Register a second slot that is NOT a member of the trust store.
    const auto unrelated_slot = registry->RegisterSlot(MakeSlotConfig("unrelated", m_empty_slot_kv));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "tls-roots";
    ts_cfg.access_policy.allowed_write_uids = {0U};
    ts_cfg.members.push_back(cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kSharedStatic});

    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());

    const auto ts_handle = manager.ResolveByName("tls-roots").value();

    const auto result = manager.EnableMember(ts_handle, unrelated_slot, kClientA);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);

    const auto result2 = manager.DisableMember(ts_handle, unrelated_slot, kClientA);
    EXPECT_FALSE(result2.has_value());
    EXPECT_EQ(result2.error(), score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
}

// A CRL written through the trust store drops only the slot's CRL cache. A certificate that is
// still referenced keeps being served from the certificate cache.
TEST_F(TrustStoreManagerTest, StoreCrlForMember_KeepsCachedCertificate)
{
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    const auto slot_handle = registry->RegisterSlot(MakeSlotConfig("empty-anchor", m_empty_slot_kv));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "mutable-store";
    ts_cfg.access_policy.allowed_write_uids = {0U};
    ts_cfg.members.push_back(
        cert::TrustStoreMemberConfig{"empty-anchor", cert::TrustStoreMemberKind::kExclusiveMutable});

    auto slot_manager = MakeSlotManager(registry);
    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, slot_manager).has_value());
    const auto ts_handle = manager.ResolveByName("mutable-store").value();

    auto cert = ParseCert(m_root_cert);
    ASSERT_NE(cert, nullptr);
    ASSERT_TRUE(manager.AddMember(ts_handle, cert, kClientA).has_value());

    const auto first = slot_manager->LoadCertificate(slot_handle, kClientA);
    ASSERT_TRUE(first.has_value());

    const std::vector<std::uint8_t> crl{0xD0U, 0xD1U, 0xD2U};
    const cert::CrlData crl_data{crl, score::crypto::FormatType::kDer};
    ASSERT_TRUE(manager.StoreCrlForMember(ts_handle, slot_handle, crl_data, kClientA).has_value());

    const auto second = slot_manager->LoadCertificate(slot_handle, kClientA);
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(second.value().get(), first.value().get());
}

// ---------------------------------------------------------------------------
// Trust-store state persistence — after DisableMember, a second manager
// instance loading from the same descriptor must see the slot as disabled.
// ---------------------------------------------------------------------------

TEST_F(TrustStoreManagerTest, PersistState_DisabledMemberSurvivesReload)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_management__persistence");
    RecordProperty("Description",
                   "Persists a disabled trust-store member and restores that state in a newly loaded manager.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    // Need a deployment path for the trust store itself (stores enabled/disabled state).
    const auto ts_kv = m_dir / "ts_state.kv";
    // Create an empty descriptor so DeploymentLoader finds the file on second load.
    storage::DeploymentDescriptor empty_desc;
    ASSERT_TRUE(storage::KvDeploymentWriter{}.Write(ts_kv.string(), empty_desc).has_value());

    auto registry = std::make_shared<cert::CertSlotRegistry>();
    const auto slot = registry->RegisterSlot(StaticSlotConfig("root-anchor"));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "persist-store";
    ts_cfg.access_policy.allowed_write_uids = {0U};
    ts_cfg.deployment_path = ts_kv.string();
    ts_cfg.deployment_format = "kv";
    ts_cfg.members.push_back(cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kSharedStatic});

    {
        cert::TrustStoreManager manager;
        ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());

        const auto ts_handle = manager.ResolveByName("persist-store").value();
        auto store = manager.GetStore(ts_handle);
        // Confirm anchor is visible before disabling.
        auto before = store->GetAnchors();
        ASSERT_TRUE(before.has_value());
        ASSERT_EQ(before->size(), 1U);

        // Disable and persist.
        ASSERT_TRUE(manager.DisableMember(ts_handle, slot, kClientA).has_value());
    }

    // Second manager instance — simulates daemon restart.
    cert::TrustStoreManager manager2;
    ASSERT_TRUE(manager2.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());

    const auto ts_handle2 = manager2.ResolveByName("persist-store").value();
    auto store2 = manager2.GetStore(ts_handle2);
    ASSERT_NE(store2, nullptr);

    // The disabled state was persisted; GetAnchors must return empty.
    auto after_reload = store2->GetAnchors();
    ASSERT_TRUE(after_reload.has_value());
    EXPECT_EQ(after_reload->size(), 0U);
}

// ---------------------------------------------------------------------------
// Trust-store state without a deployment path — member state is held in memory
// only, so it lasts for the life of the manager and is reset by a reload.
// ---------------------------------------------------------------------------

TEST_F(TrustStoreManagerTest, PersistState_EmptyDeploymentPath_DisabledMemberIsEnabledAfterReload)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_management__persistence");
    RecordProperty("Description",
                   "Without a deployment path a disable takes effect in memory and is not restored by a reload.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    auto registry = std::make_shared<cert::CertSlotRegistry>();
    const auto slot = registry->RegisterSlot(StaticSlotConfig("root-anchor"));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "memory-store";
    ts_cfg.access_policy.allowed_write_uids = {0U};
    ts_cfg.members.push_back(cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kSharedStatic});

    {
        cert::TrustStoreManager manager;
        ASSERT_TRUE(manager.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());

        const auto ts_handle = manager.ResolveByName("memory-store").value();
        auto store = manager.GetStore(ts_handle);
        ASSERT_NE(store, nullptr);

        // The disable succeeds although nothing is written.
        ASSERT_TRUE(manager.DisableMember(ts_handle, slot, kClientA).has_value());
        auto disabled = store->GetAnchors();
        ASSERT_TRUE(disabled.has_value());
        EXPECT_EQ(disabled->size(), 0U);
    }

    // A reloaded manager starts from the configuration, so the member is enabled again.
    cert::TrustStoreManager reloaded;
    ASSERT_TRUE(reloaded.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());
    const auto reloaded_handle = reloaded.ResolveByName("memory-store").value();
    auto reloaded_store = reloaded.GetStore(reloaded_handle);
    ASSERT_NE(reloaded_store, nullptr);
    auto anchors = reloaded_store->GetAnchors();
    ASSERT_TRUE(anchors.has_value());
    EXPECT_EQ(anchors->size(), 1U);
}

// Without a deployment path the acceptance of a conditional member is also held in memory only.
// A content change that was not acknowledged is therefore accepted again by a reloaded manager.
TEST_F(TrustStoreManagerTest, ConditionalExternal_EmptyDeploymentPath_UnacknowledgedChangeIsAcceptedAfterReload)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_management__persistence");
    RecordProperty("Description",
                   "Without a deployment path an unacknowledged change to a conditional member is accepted by a "
                   "reloaded manager, because the accepted fingerprint was not persisted.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    auto registry = std::make_shared<cert::CertSlotRegistry>();
    auto slot_config = MakeSlotConfig("root-anchor", m_root_slot_kv);
    slot_config.access_policy.allowed_uids = {0U};
    slot_config.access_policy.allowed_write_uids = {0U};
    const auto slot = registry->RegisterSlot(slot_config);

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "memory-cond-store";
    ts_cfg.access_policy.allowed_write_uids = {0U};
    ts_cfg.conditional_slot_initialization = cert::ConditionalSlotInitialization::kEnableAndAcceptCurrent;
    ts_cfg.members.push_back(
        cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kConditionalExternal});

    auto slot_manager = MakeSlotManager(registry);
    {
        cert::TrustStoreManager manager;
        ASSERT_TRUE(manager.Load({ts_cfg}, registry, slot_manager).has_value());
        const auto ts_handle = manager.ResolveByName("memory-cond-store").value();
        auto store = manager.GetStore(ts_handle);
        ASSERT_NE(store, nullptr);

        // The first read accepts the initial certificate, in memory only.
        auto initial = store->GetAnchors();
        ASSERT_TRUE(initial.has_value());
        ASSERT_EQ(initial->size(), 1U);
        EXPECT_EQ((*initial)[0]->GetSubject(), kSubjectInitial);

        // Replace the certificate without acknowledging it: the member is disabled.
        const auto updated = ParseCert("score/tests/test_vectors/certificate/basic/certificate_updated.pem");
        ASSERT_NE(updated, nullptr);
        ASSERT_TRUE(slot_manager->StoreCertificate(slot, kClientA, *updated).has_value());
        manager.NotifySlotChanged(slot);
        auto disabled = store->GetAnchors();
        ASSERT_TRUE(disabled.has_value());
        EXPECT_EQ(disabled->size(), 0U);
    }

    // A reloaded manager has no record of the rejected fingerprint and accepts the replaced certificate.
    cert::TrustStoreManager reloaded;
    ASSERT_TRUE(reloaded.Load({ts_cfg}, registry, MakeSlotManager(registry)).has_value());
    const auto reloaded_handle = reloaded.ResolveByName("memory-cond-store").value();
    auto reloaded_store = reloaded.GetStore(reloaded_handle);
    ASSERT_NE(reloaded_store, nullptr);
    auto anchors = reloaded_store->GetAnchors();
    ASSERT_TRUE(anchors.has_value());
    ASSERT_EQ(anchors->size(), 1U);
    EXPECT_EQ((*anchors)[0]->GetSubject(), kSubjectUpdated);
}

// ---------------------------------------------------------------------------
// NotifySlotChanged — scoped refresh of the affected member only.
// ---------------------------------------------------------------------------

/// Test-vector certificate with subject kSubjectInitial. Paths are relative to the workspace root.
static constexpr const char* kInitialPemPath = "score/tests/test_vectors/certificate/basic/certificate.pem";
/// Replacement certificate with subject kSubjectUpdated, used to simulate a content change in a slot.
static constexpr const char* kUpdatedPemPath = "score/tests/test_vectors/certificate/basic/certificate_updated.pem";

/// @brief Counts the anchors whose subject equals @p subject.
/// @param anchors Anchor set to inspect. Null entries are skipped.
/// @param subject Subject string to match exactly, as returned by CertObject::GetSubject().
/// @return Number of matching anchors; 0 when none match.
int CountWithSubject(const std::vector<cert::CertObject::Sptr>& anchors, std::string_view subject)
{
    return static_cast<int>(std::count_if(anchors.begin(), anchors.end(), [subject](const cert::CertObject::Sptr& c) {
        return c && c->GetSubject() == subject;
    }));
}

TEST_F(TrustStoreManagerTest, NotifySlotChanged_ReloadsOnlyTheChangedMember)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_mgmt__trust_stores");
    RecordProperty("Description",
                   "A slot change refreshes only the affected member; an unchanged member keeps its cached anchor "
                   "even when its backing file changes without a notification.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto other_cert = m_dir / "other_ca.pem";
    const auto other_kv = m_dir / "other_ca.kv";
    ASSERT_TRUE(
        std::filesystem::copy_file(kInitialPemPath, other_cert, std::filesystem::copy_options::overwrite_existing));
    WriteSlotDescriptor(other_kv, other_cert);

    const auto updated = ParseCert(kUpdatedPemPath);
    ASSERT_NE(updated, nullptr);

    auto registry = std::make_shared<cert::CertSlotRegistry>();
    auto root_config = MakeSlotConfig("root-anchor", m_root_slot_kv);
    root_config.access_policy.allowed_uids = {0U};
    root_config.access_policy.allowed_write_uids = {0U};
    const auto root_slot = registry->RegisterSlot(root_config);
    const auto other_slot = registry->RegisterSlot(MakeSlotConfig("other-anchor", other_kv));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "multi-store";
    ts_cfg.members.push_back(cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kSharedStatic});
    ts_cfg.members.push_back(cert::TrustStoreMemberConfig{"other-anchor", cert::TrustStoreMemberKind::kSharedStatic});

    auto slot_manager = MakeSlotManager(registry);
    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, slot_manager).has_value());
    const auto ts_handle = manager.ResolveByName("multi-store").value();
    auto store = manager.GetStore(ts_handle);
    ASSERT_NE(store, nullptr);

    // Bind the store so that its cache is warm: only the changed member is refreshed.
    ASSERT_TRUE(manager.AddRef(ts_handle, kClientA).has_value());

    auto loaded = store->GetAnchors();
    ASSERT_TRUE(loaded.has_value());
    ASSERT_EQ(loaded->size(), 2U);
    EXPECT_EQ(CountWithSubject(*loaded, kSubjectInitial), 2);

    // The other member's file changes on disk without any notification.
    ASSERT_TRUE(
        std::filesystem::copy_file(kUpdatedPemPath, other_cert, std::filesystem::copy_options::overwrite_existing));

    ASSERT_TRUE(slot_manager->StoreCertificate(root_slot, kClientA, *updated).has_value());
    manager.NotifySlotChanged(root_slot);

    auto after_root_update = store->GetAnchors();
    ASSERT_TRUE(after_root_update.has_value());
    ASSERT_EQ(after_root_update->size(), 2U);
    EXPECT_EQ(CountWithSubject(*after_root_update, kSubjectUpdated), 1);
    EXPECT_EQ(CountWithSubject(*after_root_update, kSubjectInitial), 1);

    manager.NotifySlotChanged(other_slot);
    auto after_other_update = store->GetAnchors();
    ASSERT_TRUE(after_other_update.has_value());
    ASSERT_EQ(after_other_update->size(), 2U);
    EXPECT_EQ(CountWithSubject(*after_other_update, kSubjectUpdated), 2);
}

TEST_F(TrustStoreManagerTest, NotifySlotChanged_ConditionalMember_DisabledOnlyWhenItsOwnSlotChanges)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_mgmt__trust_stores");
    RecordProperty("Description",
                   "A conditional member is disabled only when its own slot changes; a change to a shared member "
                   "leaves it enabled.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto other_cert = m_dir / "other_ca.pem";
    const auto other_kv = m_dir / "other_ca.kv";
    ASSERT_TRUE(
        std::filesystem::copy_file(kInitialPemPath, other_cert, std::filesystem::copy_options::overwrite_existing));
    WriteSlotDescriptor(other_kv, other_cert);

    const auto updated = ParseCert(kUpdatedPemPath);
    ASSERT_NE(updated, nullptr);

    auto registry = std::make_shared<cert::CertSlotRegistry>();
    auto root_config = MakeSlotConfig("root-anchor", m_root_slot_kv);
    root_config.access_policy.allowed_uids = {0U};
    root_config.access_policy.allowed_write_uids = {0U};
    const auto root_slot = registry->RegisterSlot(root_config);
    auto other_config = MakeSlotConfig("other-anchor", other_kv);
    other_config.access_policy.allowed_uids = {0U};
    other_config.access_policy.allowed_write_uids = {0U};
    const auto other_slot = registry->RegisterSlot(other_config);

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "conditional-scope-store";
    ts_cfg.access_policy.allowed_write_uids = {0U};
    ts_cfg.conditional_slot_initialization = cert::ConditionalSlotInitialization::kEnableAndAcceptCurrent;
    ts_cfg.members.push_back(
        cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kConditionalExternal});
    ts_cfg.members.push_back(cert::TrustStoreMemberConfig{"other-anchor", cert::TrustStoreMemberKind::kSharedStatic});

    auto slot_manager = MakeSlotManager(registry);
    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, slot_manager).has_value());
    const auto ts_handle = manager.ResolveByName("conditional-scope-store").value();
    auto store = manager.GetStore(ts_handle);
    ASSERT_NE(store, nullptr);

    // Bind the store so that its cache is warm and the notification refreshes it.
    ASSERT_TRUE(manager.AddRef(ts_handle, kClientA).has_value());

    auto loaded = store->GetAnchors();
    ASSERT_TRUE(loaded.has_value());
    ASSERT_EQ(loaded->size(), 2U);

    ASSERT_TRUE(slot_manager->StoreCertificate(other_slot, kClientA, *updated).has_value());
    manager.NotifySlotChanged(other_slot);
    auto after_shared_update = store->GetAnchors();
    ASSERT_TRUE(after_shared_update.has_value());
    ASSERT_EQ(after_shared_update->size(), 2U);
    EXPECT_EQ(CountWithSubject(*after_shared_update, kSubjectInitial), 1);
    EXPECT_EQ(CountWithSubject(*after_shared_update, kSubjectUpdated), 1);

    ASSERT_TRUE(slot_manager->StoreCertificate(root_slot, kClientA, *updated).has_value());
    manager.NotifySlotChanged(root_slot);
    auto after_conditional_update = store->GetAnchors();
    ASSERT_TRUE(after_conditional_update.has_value());
    ASSERT_EQ(after_conditional_update->size(), 1U);
    EXPECT_EQ((*after_conditional_update)[0]->GetSubject(), kSubjectUpdated);
}

TEST_F(TrustStoreManagerTest, NotifySlotChanged_ConditionalMember_IdenticalRewriteKeepsMemberEnabled)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_mgmt__trust_stores");
    RecordProperty("Description",
                   "Re-storing identical content in a conditional member's slot does not disable the member; "
                   "the fingerprint matches the accepted value.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    auto registry = std::make_shared<cert::CertSlotRegistry>();
    auto root_config = MakeSlotConfig("root-anchor", m_root_slot_kv);
    root_config.access_policy.allowed_uids = {0U};
    root_config.access_policy.allowed_write_uids = {0U};
    const auto root_slot = registry->RegisterSlot(root_config);

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "identical-rewrite-store";
    ts_cfg.access_policy.allowed_write_uids = {0U};
    ts_cfg.conditional_slot_initialization = cert::ConditionalSlotInitialization::kEnableAndAcceptCurrent;
    ts_cfg.members.push_back(
        cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kConditionalExternal});

    auto slot_manager = MakeSlotManager(registry);
    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, slot_manager).has_value());
    const auto ts_handle = manager.ResolveByName("identical-rewrite-store").value();
    auto store = manager.GetStore(ts_handle);
    ASSERT_NE(store, nullptr);

    // Bind the store so that its cache is warm and the notification refreshes it.
    ASSERT_TRUE(manager.AddRef(ts_handle, kClientA).has_value());

    auto initial = store->GetAnchors();
    ASSERT_TRUE(initial.has_value());
    ASSERT_EQ(initial->size(), 1U);

    const auto same_cert = ParseCert(kInitialPemPath);
    ASSERT_NE(same_cert, nullptr);
    ASSERT_TRUE(slot_manager->StoreCertificate(root_slot, kClientA, *same_cert).has_value());
    manager.NotifySlotChanged(root_slot);

    auto after = store->GetAnchors();
    ASSERT_TRUE(after.has_value());
    ASSERT_EQ(after->size(), 1U);
    EXPECT_EQ((*after)[0]->GetSubject(), kSubjectInitial);
}

TEST_F(TrustStoreManagerTest, NotifySlotChanged_BeforeFirstLoad_NextReadSeesNewContent)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_mgmt__trust_stores");
    RecordProperty("Description",
                   "A slot change notified before the store has loaded any anchors is reflected by the first read.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto updated = ParseCert(kUpdatedPemPath);
    ASSERT_NE(updated, nullptr);

    auto registry = std::make_shared<cert::CertSlotRegistry>();
    auto root_config = MakeSlotConfig("root-anchor", m_root_slot_kv);
    root_config.access_policy.allowed_uids = {0U};
    root_config.access_policy.allowed_write_uids = {0U};
    const auto root_slot = registry->RegisterSlot(root_config);

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "unloaded-store";
    ts_cfg.members.push_back(cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kSharedStatic});

    auto slot_manager = MakeSlotManager(registry);
    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, slot_manager).has_value());
    const auto ts_handle = manager.ResolveByName("unloaded-store").value();
    auto store = manager.GetStore(ts_handle);
    ASSERT_NE(store, nullptr);

    ASSERT_TRUE(slot_manager->StoreCertificate(root_slot, kClientA, *updated).has_value());
    manager.NotifySlotChanged(root_slot);

    auto anchors = store->GetAnchors();
    ASSERT_TRUE(anchors.has_value());
    ASSERT_EQ(anchors->size(), 1U);
    EXPECT_EQ((*anchors)[0]->GetSubject(), kSubjectUpdated);
}

// ---------------------------------------------------------------------------
// Concurrency — readers of the anchor and CRL caches racing slot updates.
// ---------------------------------------------------------------------------

/// One writer repeatedly replaces the certificate in a shared-static slot of a warm trust store while
/// several readers call GetAnchors() and GetCrls(). The writer alternates between the initial and the
/// updated certificate, so the anchor always has one of those two subjects.
///
/// The test checks two things:
///   - No read is inconsistent. Each GetAnchors() call returns exactly one anchor whose subject is one of
///     the two certificates. Any other result is counted as a violation. Errors count too.
///   - The last write wins. After the writer finishes, the store holds the certificate from the final write.
///     Write i (0-based) installs the updated certificate when i is even and the initial one when i is odd,
///     so the last of the kUpdates writes is kUpdates - 1.
TEST_F(TrustStoreManagerTest, ConcurrentReads_DuringSlotUpdates_ObserveCompleteAnchorSet_LastWriteWins)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_mgmt__tstr_cnsstncy");
    RecordProperty("Description",
                   "Concurrent anchor and CRL reads during repeated slot writes always observe a complete anchor set, "
                   "and after the writer finishes the store reflects the last write.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto initial = ParseCert(kInitialPemPath);
    const auto updated = ParseCert(kUpdatedPemPath);
    ASSERT_NE(initial, nullptr);
    ASSERT_NE(updated, nullptr);

    auto registry = std::make_shared<cert::CertSlotRegistry>();
    auto root_config = MakeSlotConfig("root-anchor", m_root_slot_kv);
    root_config.access_policy.allowed_uids = {0U};
    root_config.access_policy.allowed_write_uids = {0U};
    const auto root_slot = registry->RegisterSlot(root_config);

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "race-store";
    ts_cfg.members.push_back(cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kSharedStatic});

    auto slot_manager = MakeSlotManager(registry);
    cert::TrustStoreManager manager;
    ASSERT_TRUE(manager.Load({ts_cfg}, registry, slot_manager).has_value());
    const auto ts_handle = manager.ResolveByName("race-store").value();
    auto store = manager.GetStore(ts_handle);
    ASSERT_NE(store, nullptr);

    // Bind the store so that readers are served from the warm cache while the writer updates it.
    ASSERT_TRUE(manager.AddRef(ts_handle, kClientA).has_value());

    constexpr int kUpdates = 100;
    constexpr int kReaders = 4;
    // writer_done tells the readers to stop. writes_succeeded records whether every write was accepted.
    std::atomic<bool> writer_done{false};
    std::atomic<bool> writes_succeeded{true};
    std::atomic<int> violations{0};

    // Readers loop until the writer is done. A violation is a failed read, a read without exactly one
    // anchor, or an anchor whose subject is neither certificate. GetCrls() is called only to run that
    // read path concurrently; its result is not checked.
    std::vector<std::thread> readers;
    readers.reserve(kReaders);
    for (int i = 0; i < kReaders; ++i)
    {
        readers.emplace_back([&] {
            while (!writer_done.load())
            {
                const auto anchors = store->GetAnchors();
                if (!anchors.has_value() || anchors->size() != 1U)
                {
                    violations.fetch_add(1);
                    continue;
                }
                const auto subject = (*anchors)[0]->GetSubject();
                if (subject != kSubjectInitial && subject != kSubjectUpdated)
                    violations.fetch_add(1);
                static_cast<void>(store->GetCrls());
            }
        });
    }

    // The writer stores a certificate in the slot and then notifies the trust store, as the service does
    // after each slot write. Readers sample the store while the writes are running, so they do not see
    // every intermediate state; the final check covers the state after the last write.
    std::thread writer([&] {
        for (int i = 0; i < kUpdates; ++i)
        {
            const auto& next = (i % 2 == 0) ? updated : initial;
            if (!slot_manager->StoreCertificate(root_slot, kClientA, *next).has_value())
                writes_succeeded.store(false);
            manager.NotifySlotChanged(root_slot);
        }
        writer_done.store(true);
    });

    writer.join();
    for (auto& reader : readers)
        reader.join();

    EXPECT_TRUE(writes_succeeded.load());
    EXPECT_EQ(violations.load(), 0);

    // The same parity rule as the writer: write kUpdates - 1 is the last one made.
    const auto last_expected = ((kUpdates - 1) % 2 == 0) ? kSubjectUpdated : kSubjectInitial;
    auto final_anchors = store->GetAnchors();
    ASSERT_TRUE(final_anchors.has_value());
    ASSERT_EQ(final_anchors->size(), 1U);
    EXPECT_EQ((*final_anchors)[0]->GetSubject(), last_expected);
}

}  // namespace

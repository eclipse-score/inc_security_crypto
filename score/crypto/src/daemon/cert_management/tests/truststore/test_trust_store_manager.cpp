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
// Uses the real FileBackedSlotHandler, real OpenSslCertParser, and the central
// test vectors so that trust-store anchor loading, eviction, and mutation
// operations are exercised against real certificate material — not stubs.
//
// All cert bytes come from score/tests/test_vectors/certificate/ and all slot
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

#include "score/crypto/src/daemon/cert_management/slot/file_backed_slot_handler.hpp"
#include "score/crypto/src/daemon/cert_management/truststore/trust_store_manager.hpp"
#include "score/crypto/src/daemon/common/storage/kv/kv_deployment_writer.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/cert_management/openssl_cert_parser.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

namespace
{
namespace cert = score::crypto::daemon::cert_management;
namespace dm = score::crypto::daemon::data_manager;
namespace openssl_ns = score::crypto::daemon::provider::score_provider::openssl;
namespace storage = score::crypto::daemon::common::storage;
using Error = score::crypto::daemon::common::DaemonErrorCode;

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
    void SetUp() override
    {
        m_dir = std::filesystem::temp_directory_path() / "score_ts_mgr_test";
        std::filesystem::remove_all(m_dir);
        std::filesystem::create_directories(m_dir);

        m_parser = std::make_shared<openssl_ns::OpenSslCertParser>(score::crypto::daemon::common::ProviderId{1U});

        // root-anchor: slot backed by the initial test vector cert.
        m_root_cert = m_dir / "root_ca.pem";
        m_root_slot_kv = m_dir / "root_ca.kv";
        ASSERT_TRUE(std::filesystem::copy_file("score/tests/test_vectors/certificate/certificate.pem",
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

    cert::CertSlotHandlerFactory MakeHandlerFactory()
    {
        auto parser = m_parser;
        return [parser](const cert::CertSlotConfig&) {
            return std::make_shared<cert::FileBackedSlotHandler>(parser);
        };
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
    std::shared_ptr<openssl_ns::OpenSslCertParser> m_parser;
};

// ---------------------------------------------------------------------------
// Basic: lazy anchor loading and slot membership index
// ---------------------------------------------------------------------------

TEST_F(TrustStoreManagerTest, LoadsAnchorsLazilyAndBuildsSlotMembershipIndex)
{
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    const auto slot = registry->RegisterSlot(StaticSlotConfig("root-anchor"));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "tls-roots";
    ts_cfg.members.push_back(cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kSharedStatic});

    cert::TrustStoreManager manager;
    manager.Load({ts_cfg}, registry, MakeHandlerFactory());

    // Membership index is built at Load() time without touching cert bytes.
    ASSERT_EQ(manager.GetMembershipsForSlot(slot).size(), 1U);
    EXPECT_EQ(manager.GetMembershipsForSlot(slot)[0], 0U);

    // Anchors are loaded lazily on the first GetAnchors() call.
    auto store = manager.GetStore(0U);
    ASSERT_NE(store, nullptr);
    auto anchors = store->GetAnchors();
    ASSERT_TRUE(anchors.has_value());
    ASSERT_EQ(anchors->size(), 1U);
    EXPECT_EQ((*anchors)[0]->GetSubject(), kSubjectInitial);
    EXPECT_EQ((*anchors)[0]->GetFingerprint().size(), 32U);
}

// ---------------------------------------------------------------------------
// Rejection of unknown handles — no I/O needed.
// ---------------------------------------------------------------------------

TEST(TrustStoreManagerStandaloneTest, RejectsUnknownStoreAndSlotHandles)
{
    cert::TrustStoreManager manager;
    EXPECT_EQ(manager.GetStore(0U), nullptr);
    EXPECT_EQ(manager.GetMembershipsForSlot(cert::CertSlotHandle{4U}).size(), 0U);
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
    manager.Load({ts_cfg}, registry, MakeHandlerFactory());

    const auto ts_id = manager.ResolveByName("tls-roots");
    auto store = manager.GetStore(ts_id);
    ASSERT_NE(store, nullptr);

    // Trigger initial load; drop the result so the anchor's strong ref lives
    // only inside TrustStoreHandler::m_slots (not in the test frame).
    {
        auto anchors = store->GetAnchors();
        ASSERT_TRUE(anchors.has_value());
        EXPECT_EQ((*anchors)[0]->GetSubject(), kSubjectInitial);
    }

    const cert::TrustStoreHandle ts_handle{ts_id};
    manager.AddRef(ts_handle, kClientA);
    manager.AddRef(ts_handle, kClientB);

    // Rotate cert on disk — subsequent reloads will see kSubjectUpdated.
    ASSERT_TRUE(std::filesystem::copy_file("score/tests/test_vectors/certificate/certificate_updated.pem",
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
    manager.Load({ts_cfg}, registry, MakeHandlerFactory());

    const auto ts_id = manager.ResolveByName("tls-roots");
    auto store = manager.GetStore(ts_id);
    ASSERT_NE(store, nullptr);

    // Simulate two open verification contexts for kClientA.
    const cert::TrustStoreHandle ts_handle{ts_id};
    manager.AddRef(ts_handle, kClientA);
    manager.AddRef(ts_handle, kClientA);

    // Populate anchor cache and drop the caller's strong ref.
    {
        auto anchors = store->GetAnchors();
        ASSERT_TRUE(anchors.has_value());
        EXPECT_EQ((*anchors)[0]->GetSubject(), kSubjectInitial);
    }

    // Rotate cert on disk.
    ASSERT_TRUE(std::filesystem::copy_file("score/tests/test_vectors/certificate/certificate_updated.pem",
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
    manager.Load({ts_cfg}, registry, MakeHandlerFactory());

    const auto ts_id = manager.ResolveByName("tls-roots");
    auto store = manager.GetStore(ts_id);
    ASSERT_NE(store, nullptr);

    // Initial load: one anchor present.
    auto initial = store->GetAnchors();
    ASSERT_TRUE(initial.has_value());
    ASSERT_EQ(initial->size(), 1U);
    EXPECT_EQ((*initial)[0]->GetSubject(), kSubjectInitial);

    // Disable: anchor must disappear from the store immediately.
    ASSERT_TRUE(manager.DisableMember(ts_id, slot, kClientA).has_value());
    auto after_disable = store->GetAnchors();
    ASSERT_TRUE(after_disable.has_value());
    EXPECT_EQ(after_disable->size(), 0U);

    // Re-enable: anchor must reappear with the same subject.
    ASSERT_TRUE(manager.EnableMember(ts_id, slot, kClientA).has_value());
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
    manager.Load({store_a, store_b}, registry, MakeHandlerFactory());

    // Both stores report membership for the shared slot.
    EXPECT_EQ(manager.GetMembershipsForSlot(slot).size(), 2U);

    const auto ts_id_a = manager.ResolveByName("store-a");
    const auto ts_id_b = manager.ResolveByName("store-b");
    auto anchors_a = manager.GetStore(ts_id_a)->GetAnchors();
    auto anchors_b = manager.GetStore(ts_id_b)->GetAnchors();
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
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    static_cast<void>(registry->RegisterSlot(MakeSlotConfig("empty-anchor", m_empty_slot_kv)));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "mutable-store";
    ts_cfg.access_policy.allowed_write_uids = {0U};
    ts_cfg.members.push_back(
        cert::TrustStoreMemberConfig{"empty-anchor", cert::TrustStoreMemberKind::kExclusiveMutable});

    cert::TrustStoreManager manager;
    manager.Load({ts_cfg}, registry, MakeHandlerFactory());

    const auto ts_id = manager.ResolveByName("mutable-store");
    auto store = manager.GetStore(ts_id);
    ASSERT_NE(store, nullptr);

    // Slot is empty — no anchors before AddMember.
    auto before = store->GetAnchors();
    ASSERT_TRUE(before.has_value());
    EXPECT_EQ(before->size(), 0U);

    // Parse the test vector cert to get a real CertObject to add.
    auto cert = ParseCert(m_root_cert);
    ASSERT_NE(cert, nullptr);
    EXPECT_EQ(cert->GetSubject(), kSubjectInitial);

    ASSERT_TRUE(manager.AddMember(ts_id, cert, kClientA).has_value());

    // Anchor must be visible immediately after AddMember.
    auto after = store->GetAnchors();
    ASSERT_TRUE(after.has_value());
    ASSERT_EQ(after->size(), 1U);
    EXPECT_EQ((*after)[0]->GetSubject(), kSubjectInitial);

    // Verify persistence: a fresh handler must read the cert from disk.
    cert::FileBackedSlotHandler fresh_handler{m_parser};
    const auto empty_cfg = MakeSlotConfig("empty-anchor", m_empty_slot_kv);
    auto persisted = fresh_handler.LoadCertificate(empty_cfg);
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
    manager.Load({ts_cfg}, registry, MakeHandlerFactory());

    const auto ts_id = manager.ResolveByName("mutable-store");
    auto store = manager.GetStore(ts_id);
    ASSERT_NE(store, nullptr);

    // Load the anchors to obtain the real SHA-256 fingerprint.
    auto before = store->GetAnchors();
    ASSERT_TRUE(before.has_value());
    ASSERT_EQ(before->size(), 1U);
    EXPECT_EQ((*before)[0]->GetSubject(), kSubjectInitial);

    const auto fp_span = (*before)[0]->GetFingerprint();
    ASSERT_EQ(fp_span.size(), 32U);
    const std::vector<std::uint8_t> fingerprint{fp_span.begin(), fp_span.end()};

    ASSERT_TRUE(manager.RemoveMember(ts_id, fingerprint, kClientA).has_value());

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
    ts_cfg.members.push_back(cert::TrustStoreMemberConfig{"root-anchor", cert::TrustStoreMemberKind::kSharedStatic});

    cert::TrustStoreManager manager;
    manager.Load({ts_cfg}, registry, MakeHandlerFactory());

    const auto ts_id = manager.ResolveByName("cond-store");
    auto store = manager.GetStore(ts_id);
    ASSERT_NE(store, nullptr);

    // Initial load — anchor present.
    auto initial = store->GetAnchors();
    ASSERT_TRUE(initial.has_value());
    ASSERT_EQ(initial->size(), 1U);
    EXPECT_EQ((*initial)[0]->GetSubject(), kSubjectInitial);

    // Rotate cert on disk so that AcknowledgeMemberUpdate reloads a different cert.
    ASSERT_TRUE(std::filesystem::copy_file("score/tests/test_vectors/certificate/certificate_updated.pem",
                                           m_root_cert,
                                           std::filesystem::copy_options::overwrite_existing));

    // Disable — simulates detection of an unexpected content change.
    ASSERT_TRUE(manager.DisableMember(ts_id, slot, kClientA).has_value());
    {
        auto after_disable = store->GetAnchors();
        ASSERT_TRUE(after_disable.has_value());
        EXPECT_EQ(after_disable->size(), 0U);
    }

    // Acknowledge — fresh load from disk, records accepted_fingerprint, re-enables.
    ASSERT_TRUE(manager.AcknowledgeMemberUpdate(ts_id, slot, kClientA).has_value());

    auto after_ack = store->GetAnchors();
    ASSERT_TRUE(after_ack.has_value());
    ASSERT_EQ(after_ack->size(), 1U);
    // AcknowledgeMemberUpdate reloaded from disk — must now show the rotated cert.
    EXPECT_EQ((*after_ack)[0]->GetSubject(), kSubjectUpdated);
    EXPECT_EQ((*after_ack)[0]->GetFingerprint().size(), 32U);
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
    manager.Load({ts_cfg}, registry, MakeHandlerFactory());

    const auto ts_id = manager.ResolveByName("mutable-store");

    auto cert = ParseCert(m_root_cert);
    ASSERT_NE(cert, nullptr);

    const std::vector<std::uint8_t> crl{0xC0U, 0xC1U, 0xC2U};
    const auto crl_span = score::crypto::span<const std::uint8_t>{crl.data(), crl.size()};

    ASSERT_TRUE(manager.AddMember(ts_id, cert, kClientA, crl_span, score::crypto::FormatType::kDer).has_value());

    // Verify via a fresh handler: cert and CRL are both on disk.
    cert::FileBackedSlotHandler fresh_handler{m_parser};
    const auto cfg = MakeSlotConfig("empty-anchor", m_empty_slot_kv);
    ASSERT_TRUE(fresh_handler.LoadCertificate(cfg).has_value());
    ASSERT_TRUE(fresh_handler.HasCrl(cfg));
    const auto loaded_crl = fresh_handler.LoadCrl(cfg);
    ASSERT_TRUE(loaded_crl.has_value());
    EXPECT_EQ(*loaded_crl, crl);
    EXPECT_EQ(fresh_handler.GetCrlFormat(cfg), score::crypto::FormatType::kDer);
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
    manager.Load({ts_cfg}, registry, MakeHandlerFactory());

    const auto ts_id = manager.ResolveByName("mutable-store");

    auto cert = ParseCert(m_root_cert);
    ASSERT_NE(cert, nullptr);

    // First add: cert only, no CRL.
    ASSERT_TRUE(manager.AddMember(ts_id, cert, kClientA).has_value());
    {
        cert::FileBackedSlotHandler fh{m_parser};
        const auto cfg = MakeSlotConfig("empty-anchor", m_empty_slot_kv);
        EXPECT_FALSE(fh.HasCrl(cfg));
    }

    // Second add: same cert, with CRL — upsert path.
    const std::vector<std::uint8_t> crl{0xAAU, 0xBBU, 0xCCU};
    const auto crl_span = score::crypto::span<const std::uint8_t>{crl.data(), crl.size()};
    ASSERT_TRUE(manager.AddMember(ts_id, cert, kClientA, crl_span, score::crypto::FormatType::kDer).has_value());

    cert::FileBackedSlotHandler fresh_handler{m_parser};
    const auto cfg = MakeSlotConfig("empty-anchor", m_empty_slot_kv);
    ASSERT_TRUE(fresh_handler.HasCrl(cfg));
    const auto loaded_crl = fresh_handler.LoadCrl(cfg);
    ASSERT_TRUE(loaded_crl.has_value());
    EXPECT_EQ(*loaded_crl, crl);
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
    manager.Load({ts_cfg}, registry, MakeHandlerFactory());

    const auto ts_id = manager.ResolveByName("mixed-store");

    // Parse the same cert that is already the shared-static member.
    auto cert = ParseCert(m_root_cert);
    ASSERT_NE(cert, nullptr);

    const std::vector<std::uint8_t> crl{0x01U, 0x02U};
    const auto crl_span = score::crypto::span<const std::uint8_t>{crl.data(), crl.size()};

    const auto result = manager.AddMember(ts_id, cert, kClientA, crl_span, score::crypto::FormatType::kDer);
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
    manager.Load({ts_cfg}, registry, MakeHandlerFactory());

    const auto ts_id = manager.ResolveByName("mixed-store");

    // Parse the same cert that is already the shared-static member.
    auto cert = ParseCert(m_root_cert);
    ASSERT_NE(cert, nullptr);

    // AddMember without CRL: dedup on shared-static → idempotent success.
    ASSERT_TRUE(manager.AddMember(ts_id, cert, kClientA).has_value());

    // The exclusive slot must still be empty — not consumed by AddMember.
    cert::FileBackedSlotHandler fresh_handler{m_parser};
    const auto exclusive_cfg = MakeSlotConfig("empty-anchor", m_empty_slot_kv);
    const auto state = fresh_handler.GetSlotState(exclusive_cfg);
    ASSERT_TRUE(state.has_value());
    EXPECT_EQ(*state, score::crypto::CertificateSlotState::kEmpty);
}

// ---------------------------------------------------------------------------
// ImportCrlForMember — writes CRL to the exclusive slot holding the given cert.
// ---------------------------------------------------------------------------

TEST_F(TrustStoreManagerTest, ImportCrlForMember_WritesToExclusiveSlot)
{
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    static_cast<void>(registry->RegisterSlot(MakeSlotConfig("empty-anchor", m_empty_slot_kv)));

    cert::TrustStoreConfig ts_cfg;
    ts_cfg.store_name = "mutable-store";
    ts_cfg.access_policy.allowed_write_uids = {0U};
    ts_cfg.members.push_back(
        cert::TrustStoreMemberConfig{"empty-anchor", cert::TrustStoreMemberKind::kExclusiveMutable});

    cert::TrustStoreManager manager;
    manager.Load({ts_cfg}, registry, MakeHandlerFactory());

    const auto ts_id = manager.ResolveByName("mutable-store");

    auto cert = ParseCert(m_root_cert);
    ASSERT_NE(cert, nullptr);

    // First add the cert without CRL.
    ASSERT_TRUE(manager.AddMember(ts_id, cert, kClientA).has_value());

    // Now import a CRL for that member by fingerprint.
    const auto fp_span = cert->GetFingerprint();
    const std::vector<std::uint8_t> crl{0xD0U, 0xD1U, 0xD2U};
    const auto crl_span = score::crypto::span<const std::uint8_t>{crl.data(), crl.size()};

    ASSERT_TRUE(manager.ImportCrlForMember(ts_id, fp_span, crl_span, score::crypto::FormatType::kDer).has_value());

    // Verify persistence: fresh handler must read the CRL.
    cert::FileBackedSlotHandler fresh_handler{m_parser};
    const auto cfg = MakeSlotConfig("empty-anchor", m_empty_slot_kv);
    ASSERT_TRUE(fresh_handler.HasCrl(cfg));
    const auto loaded_crl = fresh_handler.LoadCrl(cfg);
    ASSERT_TRUE(loaded_crl.has_value());
    EXPECT_EQ(*loaded_crl, crl);
}

}  // namespace

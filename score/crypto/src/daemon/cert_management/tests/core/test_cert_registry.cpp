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

#include "score/crypto/src/daemon/cert_management/core/cert_entry.hpp"
#include "score/crypto/src/daemon/cert_management/core/cert_registry.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <vector>

namespace
{
using namespace score::crypto::daemon::cert_management;

CertObject::Sptr MakeCertificate()
{
    CertChainMetadata metadata;
    metadata.subject_canonical = "CN=registry-test";
    metadata.issuer_canonical = "CN=registry-test";
    metadata.fingerprint = std::vector<std::uint8_t>(32U, 0x42U);
    return std::make_shared<CertObject>(
        std::move(metadata), std::vector<std::uint8_t>{0x01U, 0x02U}, score::crypto::FormatType::kDer);
}

TEST(CertRegistryTest, RegistersFindsAndUnregistersEphemeralCertificate)
{
    CertRegistry registry;
    auto entry = std::make_shared<CertEntry>(MakeCertificate());

    const auto id = registry.RegisterEphemeralCert(entry);

    ASSERT_NE(id, 0U);
    EXPECT_EQ(registry.Size(), 1U);
    EXPECT_EQ(registry.FindById(id), entry);
    EXPECT_TRUE(registry.Unregister(id));
    EXPECT_EQ(registry.Size(), 0U);
    EXPECT_FALSE(registry.FindById(id));
}

// RegisterSlotCert creates independent entries per call — dedup of the
// underlying CertObject bytes is handled by CertSlotManager::CertObjectCache,
// not by the registry. Two clients loading the same slot each get their own
// CertEntry so that per-client state (e.g. session CRL) cannot bleed.
TEST(CertRegistryTest, RegisterSlotCert_TwoCallsProduceTwoIndependentEntries)
{
    CertRegistry registry;
    const CertSlotHandle slot{7U};
    auto cert_obj = MakeCertificate();
    auto first = std::make_shared<CertEntry>(cert_obj, slot);
    auto second = std::make_shared<CertEntry>(cert_obj, slot);

    const auto id1 = registry.RegisterSlotCert(slot, first);
    const auto id2 = registry.RegisterSlotCert(slot, second);

    ASSERT_NE(id1, 0U);
    ASSERT_NE(id2, 0U);
    EXPECT_NE(id1, id2);
    EXPECT_EQ(registry.Size(), 2U);
    // Each ID resolves to its own CertEntry.
    EXPECT_EQ(registry.FindById(id1), first);
    EXPECT_EQ(registry.FindById(id2), second);
    // Both entries wrap the same CertObject bytes.
    EXPECT_EQ(registry.FindById(id1)->GetCertObject().get(), registry.FindById(id2)->GetCertObject().get());
}

// Two ephemeral certs registered under two different client IDs.
// CleanupClient for one must remove exactly that client's entries; the other
// client's entry must remain intact.
TEST(CertRegistryTest, CleanupClient_RemovesOnlyThatClientsEntries)
{
    using ClientId = score::crypto::daemon::data_manager::ClientId;
    static constexpr ClientId kClientA = 1U;
    static constexpr ClientId kClientB = 2U;

    CertRegistry registry;

    auto entry_a = std::make_shared<CertEntry>(MakeCertificate());
    auto entry_b = std::make_shared<CertEntry>(MakeCertificate());
    entry_a->AddRef(kClientA);
    entry_b->AddRef(kClientB);

    const auto id_a = registry.RegisterEphemeralCert(entry_a);
    const auto id_b = registry.RegisterEphemeralCert(entry_b);
    ASSERT_NE(id_a, 0U);
    ASSERT_NE(id_b, 0U);
    EXPECT_EQ(registry.Size(), 2U);

    registry.CleanupClient(kClientA);

    // Client A's entry is gone.
    EXPECT_EQ(registry.FindById(id_a), nullptr);
    // Client B's entry survives.
    EXPECT_EQ(registry.FindById(id_b), entry_b);
    EXPECT_EQ(registry.Size(), 1U);
}

// A slot cert registered for one client remains findable by ID after an
// unrelated client's entries are cleaned up.
TEST(CertRegistryTest, SlotCertPersistsAfterUnrelatedClientCleanup)
{
    using ClientId = score::crypto::daemon::data_manager::ClientId;
    static constexpr ClientId kClientA = 10U;
    static constexpr ClientId kClientB = 20U;

    CertRegistry registry;
    const CertSlotHandle slot{3U};

    auto slot_entry = std::make_shared<CertEntry>(MakeCertificate(), slot);
    auto ephemeral_entry = std::make_shared<CertEntry>(MakeCertificate());
    slot_entry->AddRef(kClientA);
    ephemeral_entry->AddRef(kClientB);

    const auto slot_id = registry.RegisterSlotCert(slot, slot_entry);
    ASSERT_NE(slot_id, 0U);
    ASSERT_NE(registry.RegisterEphemeralCert(ephemeral_entry), 0U);

    registry.CleanupClient(kClientB);

    EXPECT_EQ(registry.FindById(slot_id), slot_entry);
    EXPECT_EQ(registry.Size(), 1U);
}
}  // namespace

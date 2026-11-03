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

/// @file openssl_slot_storage_test.cpp
/// @brief Store, load and clear OpenSSL keys through a file-backed key slot.
///
/// Uses the real OpenSslKeyFactory and FileBackedSlotHandler on a private directory
/// under TEST_TMPDIR, so a key persisted with StoreKey must come back unchanged from
/// LoadKey, which is what makes a stored slot usable after a daemon restart.

#include "score/crypto/src/daemon/common/algorithm_catalog.hpp"
#include "score/crypto/src/daemon/key_management/slot/file_backed_slot_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_key_factory.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_key_handler.hpp"
#include "score/tests/utility/test_utility.hpp"

#include <gtest/gtest.h>

#include <sys/stat.h>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace km = score::crypto::daemon::key_management;
namespace ossl = score::crypto::daemon::provider::openssl;
using score::crypto::KeyOperationPermission;
using score::crypto::KeySlotState;
using score::crypto::daemon::common::DaemonErrorCode;

namespace
{

score::crypto::AlgorithmDescriptor Row(std::string_view name)
{
    const auto row = score::crypto::GetAlgorithmDescriptor(name);
    EXPECT_TRUE(row.has_value()) << "not in the catalog: " << name;
    return row.value_or(score::crypto::AlgorithmDescriptor{});
}

/// The bytes a key would be persisted as; equal bytes mean the same key.
std::vector<std::uint8_t> Serialized(const km::IKeyHandler& handler)
{
    const auto serialized = handler.SerializeForStorage();
    EXPECT_TRUE(serialized.has_value());
    return serialized.has_value() ? serialized.value().bytes : std::vector<std::uint8_t>{};
}

class OpenSslSlotStorageTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        const char* const test_tmpdir = std::getenv("TEST_TMPDIR");
        const std::filesystem::path root =
            (test_tmpdir != nullptr) ? std::filesystem::path{test_tmpdir} : std::filesystem::temp_directory_path();
        m_dir = root / ("score_crypto_slot_storage_" +
                        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::error_code error;
        ASSERT_TRUE(std::filesystem::create_directories(m_dir, error)) << error.message();

        m_factory = std::make_shared<ossl::OpenSslKeyFactory>(0);  // OPENSSL provider ID
        m_slot_handler = std::make_shared<km::FileBackedSlotHandler>(m_factory);
    }

    void TearDown() override
    {
        std::error_code ignored;
        std::filesystem::remove_all(m_dir, ignored);
    }

    /// A slot for @p algorithm whose descriptor points at a key file that does not exist yet.
    km::KeySlotConfig MakeSlot(const std::string& algorithm, KeyOperationPermission allowed)
    {
        const auto descriptor = m_dir / (algorithm + ".kv");
        {
            std::ofstream out{descriptor};
            out << "[key]\nkey_path=" << (m_dir / (algorithm + ".key")).string() << "\nkey_format=der\n";
        }
        km::KeySlotConfig slot{};
        slot.slot_name = "test/" + algorithm;
        slot.algorithm = algorithm;
        slot.allowed_operations = allowed;
        slot.deployment_path = descriptor.string();
        slot.deployment_format = "kv";
        return slot;
    }

    km::IKeyHandler::Sptr Generate(std::string_view algorithm, KeyOperationPermission permissions)
    {
        km::KeyGenerationRequest request{};
        request.algorithm = Row(algorithm);
        request.permissions = permissions;
        auto generated = m_factory->GenerateKey(request);
        EXPECT_TRUE(generated.has_value()) << "GenerateKey failed for " << algorithm;
        return generated.has_value() ? generated.value() : nullptr;
    }

    std::filesystem::path m_dir;
    std::shared_ptr<ossl::OpenSslKeyFactory> m_factory;
    std::shared_ptr<km::FileBackedSlotHandler> m_slot_handler;
};

// The key has no kExport permission: persisting it in its own slot is not an export.
TEST_F(OpenSslSlotStorageTest, StoreThenLoad_SymmetricKey_ReturnsTheSameKey)
{
    const auto slot = MakeSlot("HMAC-SHA256", KeyOperationPermission::kMac);
    const auto key = Generate("HMAC-SHA256", KeyOperationPermission::kMac);
    ASSERT_NE(key, nullptr);

    ASSERT_TRUE(m_slot_handler->StoreKey(slot, *key).has_value());
    EXPECT_EQ(m_slot_handler->GetSlotState(slot).value(), KeySlotState::kOccupied);

    const auto loaded = m_slot_handler->LoadKey(slot);
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(Serialized(*loaded.value()), Serialized(*key));
}

TEST_F(OpenSslSlotStorageTest, StoreThenLoad_EcKeyPair_ReturnsTheSameKey)
{
    const auto slot = MakeSlot("ECDSA-P256", KeyOperationPermission::kSign | KeyOperationPermission::kVerify);
    const auto key = Generate("ECDSA-P256", KeyOperationPermission::kSign);
    ASSERT_NE(key, nullptr);

    ASSERT_TRUE(m_slot_handler->StoreKey(slot, *key).has_value());

    const auto loaded = m_slot_handler->LoadKey(slot);
    ASSERT_TRUE(loaded.has_value());
    EXPECT_TRUE(score::crypto::HasPermission(loaded.value()->GetHandle().permissions, KeyOperationPermission::kSign))
        << "the private half must survive the round trip";
    EXPECT_EQ(Serialized(*loaded.value()), Serialized(*key));
}

TEST_F(OpenSslSlotStorageTest, StoreThenLoad_PublicOnlyEcKey_ReturnsTheSameKey)
{
    const auto spki = tests::utility::read_bin("score/tests/test_vectors/ecdsa/P256-SHA256/siggen_public_key.der");
    km::KeyImportRequest request{};
    request.key_data = spki.data();
    request.key_data_size = spki.size();
    request.algorithm = Row("ECDSA-P256");
    request.permissions = KeyOperationPermission::kVerify;
    auto imported = m_factory->ImportKey(request);
    ASSERT_TRUE(imported.has_value());
    const auto slot = MakeSlot("ECDSA-P256", KeyOperationPermission::kVerify);

    ASSERT_TRUE(m_slot_handler->StoreKey(slot, *imported.value()).has_value());

    EXPECT_EQ(Serialized(*imported.value()), spki) << "a public-only key is stored as its SubjectPublicKeyInfo";
    const auto loaded = m_slot_handler->LoadKey(slot);
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(Serialized(*loaded.value()), spki);
}

TEST_F(OpenSslSlotStorageTest, StoredKeyFile_IsOwnerOnly)
{
    const auto slot = MakeSlot("HMAC-SHA256", KeyOperationPermission::kMac);
    const auto key = Generate("HMAC-SHA256", KeyOperationPermission::kMac);
    ASSERT_NE(key, nullptr);

    ASSERT_TRUE(m_slot_handler->StoreKey(slot, *key).has_value());

    struct stat status{};
    ASSERT_EQ(::stat((m_dir / "HMAC-SHA256.key").c_str(), &status), 0);
    EXPECT_EQ(status.st_mode & 0777U, 0600U);
}

// Replacing a key is ClearSlot then StoreKey; a direct second store is refused.
TEST_F(OpenSslSlotStorageTest, Replace_RequiresClearFirst)
{
    const auto slot = MakeSlot("HMAC-SHA256", KeyOperationPermission::kMac);
    const auto first = Generate("HMAC-SHA256", KeyOperationPermission::kMac);
    const auto second = Generate("HMAC-SHA256", KeyOperationPermission::kMac);
    ASSERT_NE(first, nullptr);
    ASSERT_NE(second, nullptr);
    ASSERT_TRUE(m_slot_handler->StoreKey(slot, *first).has_value());

    const auto refused = m_slot_handler->StoreKey(slot, *second);
    ASSERT_FALSE(refused.has_value());
    EXPECT_EQ(refused.error(), DaemonErrorCode::kKeySlotOccupied);
    EXPECT_EQ(Serialized(*m_slot_handler->LoadKey(slot).value()), Serialized(*first));

    ASSERT_TRUE(m_slot_handler->ClearSlot(slot).has_value());
    ASSERT_TRUE(m_slot_handler->StoreKey(slot, *second).has_value());
    EXPECT_EQ(Serialized(*m_slot_handler->LoadKey(slot).value()), Serialized(*second));
}

TEST_F(OpenSslSlotStorageTest, KeyOfAnotherAlgorithm_IsRefused)
{
    const auto slot = MakeSlot("HMAC-SHA256", KeyOperationPermission::kMac);
    const auto key = Generate("ECDSA-P256", KeyOperationPermission::kSign);
    ASSERT_NE(key, nullptr);

    const auto result = m_slot_handler->StoreKey(slot, *key);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kAlgorithmMismatch);
    EXPECT_EQ(m_slot_handler->GetSlotState(slot).value(), KeySlotState::kEmpty);
}

TEST_F(OpenSslSlotStorageTest, ReleasedKey_IsNotStored)
{
    const auto slot = MakeSlot("HMAC-SHA256", KeyOperationPermission::kMac);
    const auto key = Generate("HMAC-SHA256", KeyOperationPermission::kMac);
    ASSERT_NE(key, nullptr);
    ASSERT_TRUE(key->Release().has_value());

    const auto result = m_slot_handler->StoreKey(slot, *key);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(m_slot_handler->GetSlotState(slot).value(), KeySlotState::kEmpty);
}

}  // namespace

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

#include "score/crypto/src/daemon/provider/score_provider/iav_primula/key_management/iav_primula_key_factory.hpp"
#include "score/crypto/src/daemon/provider/score_provider/iav_primula/key_management/iav_primula_key_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/iav_primula/key_management/iav_primula_shared_secret_handler.hpp"

#include "score/crypto/src/api/types/common.hpp"

#include <gtest/gtest.h>

namespace
{
using namespace score::crypto::daemon;
using namespace score::crypto::daemon::provider::score_provider::iav_primula;

key_management::ProviderKeyHandle KemHandle(key_management::KeyMaterialKind kind)
{
    key_management::ProviderKeyHandle handle{};
    handle.provider_id = common::ProviderId{7U};
    handle.algorithm = "ML-KEM-768";
    handle.is_asymmetric = true;
    handle.material_kind = kind;
    handle.permissions = score::crypto::KeyOperationPermission::kAgree;
    return handle;
}

// ---------------------------------------------------------------------------
// Import validation
// ---------------------------------------------------------------------------

TEST(IavPrimulaKeyManagementTest, RejectsInvalidAlgorithmsAndKeys)
{
    IavPrimulaKeyFactory factory{common::ProviderId{7U}};
    key_management::KeyImportRequest request{};
    request.format = score::crypto::FormatType::kRaw;

    // KEM public-key import validates the same public-key size as ML-DSA.
    request.algorithm = "ML-KEM-768";
    std::vector<std::uint8_t> kem_key(1184U);
    request.key_data = kem_key.data();
    request.key_data_size = kem_key.size() - 1U;
    auto unsupported_result = factory.ImportKey(request);
    ASSERT_FALSE(unsupported_result.has_value());
    EXPECT_EQ(unsupported_result.error(), common::DaemonErrorCode::kInvalidArgument);

    // ML-DSA-44 public keys contain 1312 bytes; import one byte less
    // deliberately to verify key-size validation.
    request.algorithm = "ML-DSA-44";
    std::vector<std::uint8_t> key(1312U);
    request.key_data = key.data();
    request.key_data_size = key.size() - 1U;
    auto invalid_result = factory.ImportKey(request);
    ASSERT_FALSE(invalid_result.has_value());
    EXPECT_EQ(invalid_result.error(), common::DaemonErrorCode::kInvalidArgument);
}

// ---------------------------------------------------------------------------
// Public-key ownership and lifecycle
// ---------------------------------------------------------------------------

TEST(IavPrimulaKeyManagementTest, CopiesExportsAndReleasesPublicKey)
{
    key_management::ProviderKeyHandle handle{};
    handle.permissions = score::crypto::KeyOperationPermission::kExport;
    // Use synthetic public-key material to verify that the handler copies it.
    std::vector<std::uint8_t> public_key(8U, 0xA5U);
    IavPrimulaKeyHandler key{nullptr, public_key, handle};
    public_key[0] = 0U;

    // Export must return the copied key data, not the modified source vector.
    auto exported = key.Export();
    ASSERT_TRUE(exported.has_value());
    EXPECT_EQ(exported->bytes, std::vector<std::uint8_t>(8U, 0xA5U));

    // Releasing the key prevents subsequent export operations.
    EXPECT_TRUE(key.Release().has_value());
    auto released_export = key.Export();
    ASSERT_FALSE(released_export.has_value());
    EXPECT_EQ(released_export.error(), common::DaemonErrorCode::kKeyOperationNotPermitted);
}

// ---------------------------------------------------------------------------
// Imported public-key permissions
// ---------------------------------------------------------------------------

score::crypto::Expected<key_management::IKeyHandler::Sptr, common::DaemonErrorCode> ImportPublicKey(
    IavPrimulaKeyFactory& factory,
    const std::vector<std::uint8_t>& public_key,
    score::crypto::KeyOperationPermission permissions)
{
    key_management::KeyImportRequest request{};
    request.algorithm = "ML-DSA-44";
    request.key_data = public_key.data();
    request.key_data_size = public_key.size();
    request.format = score::crypto::FormatType::kRaw;
    request.permissions = permissions;
    return factory.ImportKey(request);
}

TEST(IavPrimulaKeyManagementTest, ImportedPublicKeyUsesPublicPermissionsOnly)
{
    using Permission = score::crypto::KeyOperationPermission;
    IavPrimulaKeyFactory factory{common::ProviderId{7U}};
    const std::vector<std::uint8_t> public_key(1312U, 0xA5U);

    auto imported = ImportPublicKey(factory, public_key, Permission::kExport);
    ASSERT_TRUE(imported.has_value());
    const auto& handle = imported.value()->GetHandle();
    EXPECT_EQ(handle.permissions, Permission::kNone);
    ASSERT_TRUE(handle.public_key_permissions.has_value());
    EXPECT_EQ(handle.public_key_permissions.value(), Permission::kExport);
}

TEST(IavPrimulaKeyManagementTest, ImportedPublicKeyWithExportPermissionCanBeExported)
{
    using Permission = score::crypto::KeyOperationPermission;
    IavPrimulaKeyFactory factory{common::ProviderId{7U}};
    const std::vector<std::uint8_t> public_key(1312U, 0xA5U);

    auto imported = ImportPublicKey(factory, public_key, Permission::kExport);
    ASSERT_TRUE(imported.has_value());
    auto exported = imported.value()->Export();
    ASSERT_TRUE(exported.has_value());
    EXPECT_EQ(exported->bytes, public_key);
}

TEST(IavPrimulaKeyManagementTest, ImportedPublicKeyWithVerifyPermissionCanVerify)
{
    using Permission = score::crypto::KeyOperationPermission;
    IavPrimulaKeyFactory factory{common::ProviderId{7U}};
    const std::vector<std::uint8_t> public_key(1312U, 0xA5U);

    auto imported = ImportPublicKey(factory, public_key, Permission::kVerify);
    ASSERT_TRUE(imported.has_value());
    const auto& handle = imported.value()->GetHandle();
    EXPECT_TRUE(score::crypto::HasPermission(
        key_management::GrantedPermissionsFor(handle, Permission::kVerify),
        Permission::kVerify));
}

TEST(IavPrimulaKeyManagementTest, ImportedPublicKeyPreservesMultiplePublicPermissions)
{
    using Permission = score::crypto::KeyOperationPermission;
    IavPrimulaKeyFactory factory{common::ProviderId{7U}};
    const std::vector<std::uint8_t> public_key(1312U, 0xA5U);
    const auto permissions = Permission::kVerify | Permission::kExport;

    auto imported = ImportPublicKey(factory, public_key, permissions);
    ASSERT_TRUE(imported.has_value());
    const auto& handle = imported.value()->GetHandle();
    ASSERT_TRUE(handle.public_key_permissions.has_value());
    EXPECT_EQ(handle.public_key_permissions.value(), permissions);
    EXPECT_TRUE(score::crypto::HasPermission(
        key_management::GrantedPermissionsFor(handle, Permission::kVerify), Permission::kVerify));
    EXPECT_TRUE(imported.value()->Export().has_value());
}

TEST(IavPrimulaKeyManagementTest, ImportedPublicKeyDeniesUnrequestedPublicPermissions)
{
    using Permission = score::crypto::KeyOperationPermission;
    IavPrimulaKeyFactory factory{common::ProviderId{7U}};
    const std::vector<std::uint8_t> public_key(1312U, 0xA5U);

    auto imported = ImportPublicKey(factory, public_key, Permission::kNone);
    ASSERT_TRUE(imported.has_value());
    const auto& handle = imported.value()->GetHandle();
    EXPECT_FALSE(score::crypto::HasPermission(
        key_management::GrantedPermissionsFor(handle, Permission::kVerify), Permission::kVerify));
    auto denied = imported.value()->Export();
    ASSERT_FALSE(denied.has_value());
    EXPECT_EQ(denied.error(), common::DaemonErrorCode::kKeyOperationNotPermitted);
}

// ---------------------------------------------------------------------------
// Key-generation dispatch
// Key-generation dispatch to backend
// ---------------------------------------------------------------------------

TEST(IavPrimulaKeyManagementTest, RoutesKemKeyGenerationToKemBackendPath)
{
    IavPrimulaKeyFactory factory{common::ProviderId{7U}};
    key_management::KeyGenerationRequest request{};
    request.algorithm = "ML-KEM-768";

    // The current Rust FFI is a deliberate placeholder and therefore returns
    // unsupported algorithm. The call still exercises the KEM-specific branch
    // in the factory; once the FFI is implemented this test should be changed
    // to assert the generated key metadata and public-key size.
    auto result = factory.GenerateKey(request);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kUnsupportedAlgorithm);
}

// ---------------------------------------------------------------------------
// KEM public-key role validation
// ---------------------------------------------------------------------------

TEST(IavPrimulaKeyManagementTest, KemOperationsRequireManagedPublicKeyRole)
{
    IavPrimulaKeyFactory factory{common::ProviderId{7U}};
    IavPrimulaKeyHandler private_key{nullptr, {}, KemHandle(key_management::KeyMaterialKind::kPrivateKey)};

    auto result = factory.GetEncapsulationCiphertextSize({private_key, "ML-KEM-768"});

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kInvalidArgument);
}

// ---------------------------------------------------------------------------
// KEM public-key permission and algorithm validation
// ---------------------------------------------------------------------------

TEST(IavPrimulaKeyManagementTest, KemPublicKeyRequiresAgreeAndMatchingAlgorithm)
{
    IavPrimulaKeyFactory factory{common::ProviderId{7U}};
    IavPrimulaKeyHandler public_key{
        nullptr, std::vector<std::uint8_t>(1184U), KemHandle(key_management::KeyMaterialKind::kPublicKey)};

    auto size = factory.GetEncapsulationCiphertextSize({public_key, "ML-KEM-768"});
    ASSERT_TRUE(size.has_value());
    EXPECT_GT(size.value(), 0U);

    auto wrong_algorithm = factory.GetEncapsulationCiphertextSize({public_key, "ML-KEM-512"});
    ASSERT_FALSE(wrong_algorithm.has_value());
    EXPECT_EQ(wrong_algorithm.error(), common::DaemonErrorCode::kInvalidArgument);

    auto no_agree_handle = KemHandle(key_management::KeyMaterialKind::kPublicKey);
    no_agree_handle.permissions = score::crypto::KeyOperationPermission::kExport;
    IavPrimulaKeyHandler no_agree_key{nullptr, std::vector<std::uint8_t>(1184U), no_agree_handle};
    auto no_agree = factory.GetEncapsulationCiphertextSize({no_agree_key, "ML-KEM-768"});
    ASSERT_FALSE(no_agree.has_value());
    EXPECT_EQ(no_agree.error(), common::DaemonErrorCode::kKeyOperationNotPermitted);
}

// ---------------------------------------------------------------------------
// KEM decapsulation input validation
// ---------------------------------------------------------------------------

TEST(IavPrimulaKeyManagementTest, DecapsulationRejectsInvalidCiphertextBeforeCallingFfi)
{
    IavPrimulaKeyFactory factory{common::ProviderId{7U}};
    IavPrimulaKeyHandler private_key{nullptr, {}, KemHandle(key_management::KeyMaterialKind::kPrivateKey)};
    const std::vector<std::uint8_t> invalid_ciphertext(1U);

    auto result = factory.DecapsulateKey(
        {private_key, "ML-KEM-768", {invalid_ciphertext.data(), invalid_ciphertext.size()}});

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kInvalidArgument);
}

// ---------------------------------------------------------------------------
// KEM shared-secret lifecycle
// ---------------------------------------------------------------------------

TEST(IavPrimulaKeyManagementTest, SharedSecretIsDeriveOnlyAndNonExportable)
{
    key_management::SecureKeyBytes bytes{32U};
    IavPrimulaSharedSecretHandler secret{std::move(bytes), common::ProviderId{7U}};

    EXPECT_EQ(secret.GetHandle().material_kind, key_management::KeyMaterialKind::kSharedSecret);
    EXPECT_EQ(secret.GetHandle().permissions, score::crypto::KeyOperationPermission::kDerive);
    EXPECT_FALSE(secret.Export().has_value());
    EXPECT_TRUE(secret.Release().has_value());
    EXPECT_EQ(secret.GetHandle().key_size, 0U);
}
}  // namespace

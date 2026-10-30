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
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/data_manager/data_manager.hpp"
#include "score/crypto/src/daemon/key_management/core/key_management_service.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_management_operations.hpp"
#include "score/crypto/src/daemon/provider/executors/key_mgmt_executor.hpp"

#include <gtest/gtest.h>

#include <memory>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

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
    if (kind == key_management::KeyMaterialKind::kPublicKey)
    {
        handle.public_key_permissions = score::crypto::KeyOperationPermission::kAgree;
    }
    else
    {
        handle.permissions = score::crypto::KeyOperationPermission::kAgree;
    }
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
// Service and executor public-key export permissions
// ---------------------------------------------------------------------------

class IavPrimulaKeyExportTest : public ::testing::Test
{
  protected:
    using Permission = score::crypto::KeyOperationPermission;
    using Error = common::DaemonErrorCode;

    void SetUp() override
    {
        auto data_manager = std::make_shared<data_manager::DataManager>();
        service = std::make_shared<key_management::KeyManagementService>(data_manager, nullptr, nullptr);
        auto parent = data_manager->addNode(kClientId, std::make_shared<data_manager::DataNode>(false));
        ASSERT_TRUE(parent.has_value());
        context.client_id = kClientId;
        context.context_node_id = parent.value();
        context.provider_id = kProviderId;
        auto factory = std::make_shared<IavPrimulaKeyFactory>(kProviderId);
        key_executor = std::make_unique<provider::crypto_executor::KeyManagementExecutor>(factory, nullptr, service);
    }

    score::crypto::Expected<common::ResponseParameters, Error> Import(
        std::string_view algorithm, const std::vector<std::uint8_t>& public_key, Permission permissions)
    {
        common::RequestParameters request{
            algorithm,
            score::cpp::span<const std::uint8_t>{public_key.data(), public_key.size()},
            static_cast<std::uint8_t>(score::crypto::FormatType::kRaw),
            static_cast<std::uint32_t>(permissions)};
        return key_executor->Execute(
            context, {common::actors::OP_ACTOR_KEY_MANAGEMENT, key_management::operations::KEY_IMPORT}, request);
    }

    score::crypto::Expected<common::ResponseParameters, Error> ExecuteExport(
        common::OperationAction action, data_manager::DataNodeId key_id)
    {
        common::RequestParameters request{
            static_cast<std::uint64_t>(key_id), static_cast<std::uint8_t>(score::crypto::FormatType::kRaw)};
        return key_executor->Execute(context, {common::actors::OP_ACTOR_KEY_MANAGEMENT, action}, request);
    }

    data_manager::DataNodeId Register(key_management::IKeyHandler::Sptr key)
    {
        auto registered = service->RegisterKeyMaterial(
            {kClientId, context.context_node_id, kProviderId}, std::move(key));
        EXPECT_TRUE(registered.has_value());
        return registered.has_value() ? registered.value().node_id : 0U;
    }

    static constexpr data_manager::ClientId kClientId{17U};
    static constexpr common::ProviderId kProviderId{7U};
    provider::crypto_executor::KeyMgmtExecutionContext context{};
    std::shared_ptr<key_management::KeyManagementService> service;
    std::unique_ptr<provider::crypto_executor::KeyManagementExecutor> key_executor;
};

TEST_F(IavPrimulaKeyExportTest, ImportedPublicPermissionsGovernExportAndExportSize)
{
    for (const auto algorithm : {std::string_view{"ML-KEM-768"}, std::string_view{"ML-DSA-44"}})
    {
        SCOPED_TRACE(algorithm);
        const std::vector<std::uint8_t> public_key(algorithm == "ML-KEM-768" ? 1184U : 1312U, 0xA5U);
        for (const auto permissions :
             {Permission::kExport, Permission::kAgree | Permission::kExport, Permission::kAgree, Permission::kNone})
        {
            SCOPED_TRACE(static_cast<std::uint32_t>(permissions));
            auto imported = Import(algorithm, public_key, permissions);
            ASSERT_TRUE(imported.has_value());
            ASSERT_EQ(imported.value().size(), 2U);
            const auto key_id = std::get<std::uint64_t>(imported.value()[0]);
            auto handler = service->ResolveKeyForOperation(kClientId, key_id);
            ASSERT_TRUE(handler.has_value());
            EXPECT_EQ(handler.value()->GetHandle().material_kind, key_management::KeyMaterialKind::kPublicKey);
            EXPECT_EQ(handler.value()->GetHandle().permissions, Permission::kNone);
            ASSERT_TRUE(handler.value()->GetHandle().public_key_permissions.has_value());
            EXPECT_EQ(handler.value()->GetHandle().public_key_permissions.value(), permissions);

            auto size = ExecuteExport(key_management::operations::KEY_GET_EXPORT_SIZE, key_id);
            auto exported = ExecuteExport(key_management::operations::KEY_EXPORT, key_id);
            if (score::crypto::HasPermission(permissions, Permission::kExport))
            {
                ASSERT_TRUE(size.has_value());
                ASSERT_EQ(size.value().size(), 1U);
                EXPECT_EQ(std::get<std::uint64_t>(size.value()[0]), public_key.size());
                ASSERT_TRUE(exported.has_value());
                ASSERT_EQ(exported.value().size(), 1U);
                EXPECT_EQ(std::get<common::OwnedBuffer>(exported.value()[0]), public_key);
            }
            else
            {
                ASSERT_FALSE(size.has_value());
                EXPECT_EQ(size.error(), Error::kKeyOperationNotPermitted);
                ASSERT_FALSE(exported.has_value());
                EXPECT_EQ(exported.error(), Error::kKeyOperationNotPermitted);
            }
        }
    }
}

TEST_F(IavPrimulaKeyExportTest, PrivateExportPermissionCannotOverridePublicKeyDenial)
{
    auto handle = KemHandle(key_management::KeyMaterialKind::kPublicKey);
    handle.permissions = Permission::kExport;
    handle.public_key_permissions = Permission::kNone;
    const auto key_id = Register(std::make_shared<IavPrimulaKeyHandler>(
        nullptr, std::vector<std::uint8_t>(1184U, 0xA5U), handle));
    ASSERT_NE(key_id, 0U);

    auto lease = service->AcquireKeyForOperation(kClientId, key_id, kProviderId, Permission::kExport);
    ASSERT_FALSE(lease.has_value());
    EXPECT_EQ(lease.error(), Error::kKeyOperationNotPermitted);
    for (const auto action : {key_management::operations::KEY_GET_EXPORT_SIZE, key_management::operations::KEY_EXPORT})
    {
        auto result = ExecuteExport(action, key_id);
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error(), Error::kKeyOperationNotPermitted);
    }
}

TEST_F(IavPrimulaKeyExportTest, UnspecifiedPublicPermissionsAllowExportAndExportSize)
{
    auto handle = KemHandle(key_management::KeyMaterialKind::kPublicKey);
    handle.public_key_permissions.reset();
    const std::vector<std::uint8_t> public_key(1184U, 0xA5U);
    const auto key_id = Register(std::make_shared<IavPrimulaKeyHandler>(nullptr, public_key, handle));
    ASSERT_NE(key_id, 0U);

    auto size = ExecuteExport(key_management::operations::KEY_GET_EXPORT_SIZE, key_id);
    ASSERT_TRUE(size.has_value());
    ASSERT_EQ(size.value().size(), 1U);
    EXPECT_EQ(std::get<std::uint64_t>(size.value()[0]), public_key.size());
    auto exported = ExecuteExport(key_management::operations::KEY_EXPORT, key_id);
    ASSERT_TRUE(exported.has_value());
    ASSERT_EQ(exported.value().size(), 1U);
    EXPECT_EQ(std::get<common::OwnedBuffer>(exported.value()[0]), public_key);
}

TEST_F(IavPrimulaKeyExportTest, NonPublicKeyRolesCannotUsePublicExportPermissions)
{
    for (const auto kind : {key_management::KeyMaterialKind::kPrivateKey,
                           key_management::KeyMaterialKind::kSymmetricKey,
                           key_management::KeyMaterialKind::kSharedSecret,
                           key_management::KeyMaterialKind::kUnspecified})
    {
        SCOPED_TRACE(static_cast<std::uint8_t>(kind));
        for (const auto public_permissions :
             {std::optional<Permission>{Permission::kExport}, std::optional<Permission>{}})
        {
            key_management::ProviderKeyHandle handle{};
            handle.provider_id = kProviderId;
            handle.material_kind = kind;
            handle.is_asymmetric = (kind == key_management::KeyMaterialKind::kPrivateKey);
            handle.permissions = Permission::kDerive;
            handle.public_key_permissions = public_permissions;
            const auto key_id = Register(
                std::make_shared<IavPrimulaKeyHandler>(nullptr, std::vector<std::uint8_t>{}, handle));
            ASSERT_NE(key_id, 0U);

            auto lease = service->AcquireKeyForOperation(kClientId, key_id, kProviderId, Permission::kExport);
            ASSERT_FALSE(lease.has_value());
            EXPECT_EQ(lease.error(), Error::kKeyOperationNotPermitted);
        }
    }
}

TEST_F(IavPrimulaKeyExportTest, PrivateAndSymmetricKeysRetainTheirOwnExportPermissions)
{
    for (const auto kind : {key_management::KeyMaterialKind::kPrivateKey, key_management::KeyMaterialKind::kSymmetricKey})
    {
        key_management::ProviderKeyHandle handle{};
        handle.provider_id = kProviderId;
        handle.material_kind = kind;
        handle.is_asymmetric = (kind == key_management::KeyMaterialKind::kPrivateKey);
        handle.permissions = Permission::kExport;
        handle.public_key_permissions = Permission::kNone;
        const auto key_id = Register(
            std::make_shared<IavPrimulaKeyHandler>(nullptr, std::vector<std::uint8_t>{}, handle));
        ASSERT_NE(key_id, 0U);

        auto lease = service->AcquireKeyForOperation(kClientId, key_id, kProviderId, Permission::kExport);
        ASSERT_TRUE(lease.has_value());
    }
}

TEST_F(IavPrimulaKeyExportTest, PrimulaSharedSecretRemainsNonExportable)
{
    const auto key_id = Register(std::make_shared<IavPrimulaSharedSecretHandler>(
        key_management::SecureKeyBytes{32U}, kProviderId));
    ASSERT_NE(key_id, 0U);
    for (const auto action : {key_management::operations::KEY_GET_EXPORT_SIZE, key_management::operations::KEY_EXPORT})
    {
        auto result = ExecuteExport(action, key_id);
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error(), Error::kKeyOperationNotPermitted);
    }
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
    no_agree_handle.public_key_permissions = score::crypto::KeyOperationPermission::kExport;
    IavPrimulaKeyHandler no_agree_key{nullptr, std::vector<std::uint8_t>(1184U), no_agree_handle};
    auto no_agree = factory.GetEncapsulationCiphertextSize({no_agree_key, "ML-KEM-768"});
    ASSERT_FALSE(no_agree.has_value());
    EXPECT_EQ(no_agree.error(), common::DaemonErrorCode::kKeyOperationNotPermitted);
}

TEST(IavPrimulaKeyManagementTest, ImportedKemPublicKeyUsesItsPublicAgreePermission)
{
    using Permission = score::crypto::KeyOperationPermission;
    IavPrimulaKeyFactory factory{common::ProviderId{7U}};
    const std::vector<std::uint8_t> public_key(1184U);
    key_management::KeyImportRequest request{};
    request.algorithm = "ML-KEM-768";
    request.key_data = public_key.data();
    request.key_data_size = public_key.size();
    request.format = score::crypto::FormatType::kRaw;

    for (const auto permissions : {Permission::kAgree, Permission::kNone, Permission::kExport})
    {
        request.permissions = permissions;
        auto imported = factory.ImportKey(request);
        ASSERT_TRUE(imported.has_value());
        EXPECT_EQ(imported.value()->GetHandle().permissions, Permission::kNone);
        EXPECT_EQ(imported.value()->GetHandle().public_key_permissions.value(), permissions);

        auto size = factory.GetEncapsulationCiphertextSize({*imported.value(), "ML-KEM-768"});
        if (permissions == Permission::kAgree)
        {
            ASSERT_TRUE(size.has_value());
            EXPECT_EQ(size.value(), 1088U);
        }
        else
        {
            ASSERT_FALSE(size.has_value());
            EXPECT_EQ(size.error(), common::DaemonErrorCode::kKeyOperationNotPermitted);
        }
    }
}

TEST(IavPrimulaKeyManagementTest, UnspecifiedPublicPermissionsRemainUnrestricted)
{
    auto handle = KemHandle(key_management::KeyMaterialKind::kPublicKey);
    handle.public_key_permissions.reset();
    IavPrimulaKeyHandler public_key{nullptr, std::vector<std::uint8_t>(1184U), handle};
    IavPrimulaKeyFactory factory{common::ProviderId{7U}};

    auto size = factory.GetEncapsulationCiphertextSize({public_key, "ML-KEM-768"});

    ASSERT_TRUE(size.has_value());
    EXPECT_EQ(size.value(), 1088U);
}

TEST(IavPrimulaKeyManagementTest, DecapsulationCannotUsePublicAgreePermission)
{
    using Permission = score::crypto::KeyOperationPermission;
    auto handle = KemHandle(key_management::KeyMaterialKind::kPrivateKey);
    handle.permissions = Permission::kNone;
    handle.public_key_permissions = Permission::kAgree;
    IavPrimulaKeyHandler private_key{nullptr, {}, handle};
    IavPrimulaKeyFactory factory{common::ProviderId{7U}};
    const std::vector<std::uint8_t> ciphertext(1088U);

    auto result = factory.DecapsulateKey(
        {private_key, "ML-KEM-768", {ciphertext.data(), ciphertext.size()}});

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kKeyOperationNotPermitted);
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

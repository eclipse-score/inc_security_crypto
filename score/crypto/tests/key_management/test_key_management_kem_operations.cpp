/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

#include "score/crypto/src/api/contexts/src/key_management_context_impl.hpp"
#include "score/crypto/src/api/control_plane/i_connection.hpp"
#include "score/crypto/src/api/data_plane/src/buffer_shm_transcoder.hpp"
#include "score/crypto/src/api/data_plane/src/shm_region_registry.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/data_manager/data_manager.hpp"
#include "score/crypto/src/daemon/key_management/core/key_management_service.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/i_key_factory.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_management_operations.hpp"
#include "score/crypto/src/daemon/provider/executors/key_mgmt_executor.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <functional>
#include <future>
#include <memory>
#include <string_view>
#include <utility>
#include <vector>

namespace
{
namespace api = score::crypto::api::control_plane;
namespace common = score::crypto::daemon::common;
namespace control = score::crypto::daemon::control_plane::protocol;
namespace data_manager = score::crypto::daemon::data_manager;
namespace key_management = score::crypto::daemon::key_management;
namespace operations = score::crypto::daemon::key_management::operations;
namespace executor = score::crypto::daemon::provider::crypto_executor;
using Error = common::DaemonErrorCode;
using Permission = score::crypto::KeyOperationPermission;

constexpr data_manager::ClientId kClientId{17U};
constexpr common::ProviderId kProviderId{3U};
constexpr std::string_view kAlgorithm{"ML-KEM-768"};
constexpr std::array<std::string_view, 3U> kKemAlgorithms{{"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}};

constexpr bool IsSupportedKemAlgorithm(std::string_view algorithm) noexcept
{
    for (const auto candidate : kKemAlgorithms)
    {
        if (candidate == algorithm)
        {
            return true;
        }
    }
    return false;
}

struct ReleaseState
{
    bool released{false};
};

class TestKeyHandler final : public key_management::IKeyHandler
{
  public:
    TestKeyHandler(key_management::ProviderKeyHandle handle, std::shared_ptr<ReleaseState> state)
        : m_handle{std::move(handle)}, m_state{std::move(state)}
    {
    }

    const key_management::ProviderKeyHandle& GetHandle() const noexcept override
    {
        return m_handle;
    }

    common::ProviderId GetProviderId() const noexcept override
    {
        return m_handle.provider_id;
    }

    score::crypto::Expected<std::monostate, Error> Release() override
    {
        m_state->released = true;
        return std::monostate{};
    }

    score::crypto::Expected<key_management::SecureKeyBytes, Error> Export() const override
    {
        return score::crypto::make_unexpected(Error::kKeyOperationNotPermitted);
    }

  private:
    key_management::ProviderKeyHandle m_handle;
    std::shared_ptr<ReleaseState> m_state;
};

key_management::IKeyHandler::Sptr MakeKey(key_management::KeyMaterialKind kind,
                                          Permission permissions,
                                          std::string_view algorithm = kAlgorithm,
                                          std::shared_ptr<ReleaseState> state = std::make_shared<ReleaseState>())
{
    key_management::ProviderKeyHandle handle{};
    handle.provider_id = kProviderId;
    handle.algorithm = *::score::crypto::GetAlgorithmDescriptor(algorithm);
    if (kind == key_management::KeyMaterialKind::kPublicKey)
    {
        handle.public_key_permissions = permissions;
    }
    else
    {
        handle.permissions = permissions;
    }
    handle.is_asymmetric = kind != key_management::KeyMaterialKind::kSharedSecret;
    handle.key_size = 32U;
    handle.material_kind = kind;
    return std::make_shared<TestKeyHandler>(std::move(handle), std::move(state));
}

class KemTestFactory final : public key_management::IKeyFactory
{
  public:
    std::size_t get_size_calls{0U};
    std::size_t encapsulate_calls{0U};
    std::size_t decapsulate_calls{0U};

    score::crypto::Expected<key_management::IKeyHandler::Sptr, Error> ImportKey(
        const key_management::KeyImportRequest& request) override
    {
        if (!IsSupportedKemAlgorithm(request.algorithm.name) || request.key_data == nullptr ||
            request.key_data_size == 0U || request.format != score::crypto::FormatType::kRaw)
        {
            return score::crypto::make_unexpected(Error::kInvalidArgument);
        }
        return MakeKey(key_management::KeyMaterialKind::kPublicKey, request.permissions, request.algorithm.name);
    }

    score::crypto::Expected<std::size_t, Error> GetEncapsulationCiphertextSize(
        const key_management::KeyEncapsulationRequest& request) const override
    {
        ++const_cast<KemTestFactory*>(this)->get_size_calls;
        if (!IsSupportedKemAlgorithm(request.algorithm.name) ||
            request.public_key.GetHandle().material_kind != key_management::KeyMaterialKind::kPublicKey)
        {
            return score::crypto::make_unexpected(Error::kInvalidArgument);
        }
        return kCiphertext.size();
    }

    score::crypto::Expected<key_management::ProviderEncapsulationResult, Error> EncapsulateKey(
        const key_management::KeyEncapsulationRequest& request) override
    {
        ++encapsulate_calls;
        if (!IsSupportedKemAlgorithm(request.algorithm.name) ||
            request.public_key.GetHandle().material_kind != key_management::KeyMaterialKind::kPublicKey)
        {
            return score::crypto::make_unexpected(Error::kInvalidArgument);
        }
        return key_management::ProviderEncapsulationResult{
            std::vector<std::uint8_t>{kCiphertext.begin(), kCiphertext.end()},
            MakeKey(key_management::KeyMaterialKind::kSharedSecret, Permission::kDerive, request.algorithm.name)};
    }

    score::crypto::Expected<key_management::IKeyHandler::Sptr, Error> DecapsulateKey(
        const key_management::KeyDecapsulationRequest& request) override
    {
        ++decapsulate_calls;
        if (!IsSupportedKemAlgorithm(request.algorithm.name) ||
            request.private_key.GetHandle().material_kind != key_management::KeyMaterialKind::kPrivateKey ||
            request.ciphertext.empty())
        {
            return score::crypto::make_unexpected(Error::kInvalidArgument);
        }
        return MakeKey(key_management::KeyMaterialKind::kSharedSecret, Permission::kDerive, request.algorithm.name);
    }

    static constexpr std::array<std::uint8_t, 4U> kCiphertext{{0x01U, 0x02U, 0x03U, 0x04U}};
};

class KeyManagementExecutorKemTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        data_manager = std::make_shared<data_manager::DataManager>();
        service = std::make_shared<key_management::KeyManagementService>(data_manager, nullptr, nullptr);
        auto parent = data_manager->addNode(kClientId, std::make_shared<data_manager::DataNode>(false));
        ASSERT_TRUE(parent.has_value());
        context.context_node_id = parent.value();
        context.client_id = kClientId;
        context.provider_id = kProviderId;
        factory = std::make_shared<KemTestFactory>();
        key_executor = std::make_unique<executor::KeyManagementExecutor>(factory, nullptr, service);
    }

    data_manager::DataNodeId RegisterSource(key_management::KeyMaterialKind kind,
                                            Permission permissions,
                                            std::string_view algorithm = kAlgorithm)
    {
        auto registered = service->RegisterKeyMaterial(
            {kClientId, context.context_node_id, kProviderId}, MakeKey(kind, permissions, algorithm));
        EXPECT_TRUE(registered.has_value());
        return registered.has_value() ? registered.value().node_id : 0U;
    }

    executor::KeyMgmtExecutionContext context{};
    std::shared_ptr<data_manager::DataManager> data_manager;
    std::shared_ptr<key_management::KeyManagementService> service;
    std::shared_ptr<KemTestFactory> factory;
    std::unique_ptr<executor::KeyManagementExecutor> key_executor;
};

class KeyManagementExecutorKemVariantTest : public KeyManagementExecutorKemTest,
                                             public ::testing::WithParamInterface<std::string_view>
{
};

// ---------------------------------------------------------------------------
// KEM encapsulation result registration
// ---------------------------------------------------------------------------

TEST_F(KeyManagementExecutorKemTest, EncapsulationRegistersADeriveOnlySecretAndWritesCiphertext)
{
    const auto public_key = RegisterSource(key_management::KeyMaterialKind::kPublicKey, Permission::kAgree);
    std::array<std::uint8_t, KemTestFactory::kCiphertext.size()> ciphertext{};
    common::RequestParameters request{std::string_view{kAlgorithm},
                                      static_cast<std::uint64_t>(public_key),
                                      score::cpp::span<std::uint8_t>{ciphertext.data(), ciphertext.size()}};

    auto result = key_executor->Execute(
        context, {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, operations::KEY_ENCAPSULATE}, request);

    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result.value().size(), 3U);
    EXPECT_EQ(std::get<std::uint64_t>(result.value()[0]), ciphertext.size());
    EXPECT_EQ(ciphertext, KemTestFactory::kCiphertext);
    const auto secret_id = std::get<std::uint64_t>(result.value()[1]);
    EXPECT_NE(secret_id, 0U);
    EXPECT_EQ(std::get<std::uint16_t>(result.value()[2]), kProviderId);
    EXPECT_EQ(factory->encapsulate_calls, 1U);

    auto secret = service->AcquireKeyForOperation(kClientId, secret_id, kProviderId, Permission::kDerive);
    ASSERT_TRUE(secret.has_value());
    EXPECT_EQ(secret.value()->GetHandle().material_kind, key_management::KeyMaterialKind::kSharedSecret);
    EXPECT_EQ(secret.value()->GetHandle().permissions, Permission::kDerive);
    EXPECT_FALSE(secret.value()->GetHandle().is_asymmetric);
}

TEST_F(KeyManagementExecutorKemTest, ImportedPublicKeyPermissionsGovernEncapsulation)
{
    const auto ciphertext = KemTestFactory::kCiphertext;
    for (const auto permissions : {Permission::kAgree, Permission::kNone, Permission::kExport})
    {
        common::RequestParameters import_request{
            std::string_view{kAlgorithm},
            static_cast<std::uint32_t>(permissions),
            static_cast<std::uint32_t>(score::crypto::FormatType::kRaw),
            score::cpp::span<const std::uint8_t>{ciphertext.data(), ciphertext.size()}};
        auto imported = key_executor->Execute(
            context, {common::actors::OP_ACTOR_KEY_MANAGEMENT, operations::KEY_IMPORT}, import_request);
        ASSERT_TRUE(imported.has_value());
        const auto public_key_id = std::get<std::uint64_t>(imported.value()[0]);

        auto handler = service->ResolveKeyForOperation(kClientId, public_key_id);
        ASSERT_TRUE(handler.has_value());
        EXPECT_EQ(handler.value()->GetHandle().permissions, Permission::kNone);
        EXPECT_EQ(handler.value()->GetHandle().public_key_permissions.value(), permissions);

        common::RequestParameters size_request{std::string_view{kAlgorithm}, public_key_id};
        auto size = key_executor->Execute(
            context, {common::actors::OP_ACTOR_KEY_MANAGEMENT, operations::KEY_GET_ENCAPSULATION_SIZE}, size_request);
        std::array<std::uint8_t, KemTestFactory::kCiphertext.size()> ciphertext_out{};
        common::RequestParameters encapsulate_request{
            std::string_view{kAlgorithm},
            public_key_id,
            score::cpp::span<std::uint8_t>{ciphertext_out.data(), ciphertext_out.size()}};
        auto encapsulated = key_executor->Execute(
            context, {common::actors::OP_ACTOR_KEY_MANAGEMENT, operations::KEY_ENCAPSULATE}, encapsulate_request);

        if (permissions == Permission::kAgree)
        {
            ASSERT_TRUE(size.has_value());
            EXPECT_EQ(std::get<std::uint64_t>(size.value()[0]), ciphertext.size());
            ASSERT_TRUE(encapsulated.has_value());
            EXPECT_EQ(encapsulated.value().size(), 3U);
        }
        else
        {
            ASSERT_FALSE(size.has_value());
            EXPECT_EQ(size.error(), Error::kKeyOperationNotPermitted);
            ASSERT_FALSE(encapsulated.has_value());
            EXPECT_EQ(encapsulated.error(), Error::kKeyOperationNotPermitted);
        }
    }
    EXPECT_EQ(factory->encapsulate_calls, 1U);
}

TEST_F(KeyManagementExecutorKemTest, PrivateKeyCannotUsePublicAgreePermission)
{
    key_management::ProviderKeyHandle handle{};
    handle.provider_id = kProviderId;
    handle.algorithm = *::score::crypto::GetAlgorithmDescriptor(kAlgorithm);
    handle.material_kind = key_management::KeyMaterialKind::kPrivateKey;
    handle.is_asymmetric = true;
    handle.permissions = Permission::kNone;
    handle.public_key_permissions = Permission::kAgree;
    auto key = std::make_shared<TestKeyHandler>(handle, std::make_shared<ReleaseState>());
    auto registered = service->RegisterKeyMaterial(
        {kClientId, context.context_node_id, kProviderId}, std::move(key));
    ASSERT_TRUE(registered.has_value());
    const auto ciphertext = KemTestFactory::kCiphertext;
    common::RequestParameters request{
        std::string_view{kAlgorithm},
        static_cast<std::uint64_t>(registered.value().node_id),
        score::cpp::span<const std::uint8_t>{ciphertext.data(), ciphertext.size()}};

    auto result = key_executor->Execute(
        context, {common::actors::OP_ACTOR_KEY_MANAGEMENT, operations::KEY_DECAPSULATE}, request);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kKeyOperationNotPermitted);
    EXPECT_EQ(factory->decapsulate_calls, 0U);
}

// ---------------------------------------------------------------------------
// KEM decapsulation result registration
// ---------------------------------------------------------------------------

TEST_F(KeyManagementExecutorKemTest, DecapsulationRegistersADeriveOnlySecret)
{
    const auto private_key = RegisterSource(key_management::KeyMaterialKind::kPrivateKey, Permission::kAgree);
    const std::array<std::uint8_t, 4U> ciphertext{{0xA0U, 0xA1U, 0xA2U, 0xA3U}};
    common::RequestParameters request{std::string_view{kAlgorithm}, static_cast<std::uint64_t>(private_key),
                                      score::cpp::span<const std::uint8_t>{ciphertext.data(), ciphertext.size()}};

    auto result = key_executor->Execute(
        context, {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, operations::KEY_DECAPSULATE}, request);

    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result.value().size(), 2U);
    const auto secret_id = std::get<std::uint64_t>(result.value()[0]);
    EXPECT_NE(secret_id, 0U);
    EXPECT_EQ(std::get<std::uint16_t>(result.value()[1]), kProviderId);
    EXPECT_EQ(factory->decapsulate_calls, 1U);

    auto secret = service->AcquireKeyForOperation(kClientId, secret_id, kProviderId, Permission::kDerive);
    ASSERT_TRUE(secret.has_value());
    EXPECT_EQ(secret.value()->GetHandle().material_kind, key_management::KeyMaterialKind::kSharedSecret);
    EXPECT_EQ(secret.value()->GetHandle().permissions, Permission::kDerive);
}

// ---------------------------------------------------------------------------
// KEM parameter-set dispatch
// ---------------------------------------------------------------------------

TEST_P(KeyManagementExecutorKemVariantTest, RoutesAllStandardKemParameterSets)
{
    const auto algorithm = GetParam();
    const auto public_key = RegisterSource(key_management::KeyMaterialKind::kPublicKey, Permission::kAgree, algorithm);
    common::RequestParameters size_request{algorithm, static_cast<std::uint64_t>(public_key)};

    auto size = key_executor->Execute(
        context,
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, operations::KEY_GET_ENCAPSULATION_SIZE},
        size_request);
    ASSERT_TRUE(size.has_value());
    EXPECT_EQ(std::get<std::uint64_t>(size.value().front()), KemTestFactory::kCiphertext.size());

    std::array<std::uint8_t, KemTestFactory::kCiphertext.size()> ciphertext_out{};
    common::RequestParameters encapsulate_request{
        algorithm,
        static_cast<std::uint64_t>(public_key),
        score::cpp::span<std::uint8_t>{ciphertext_out.data(), ciphertext_out.size()}};
    auto encapsulated = key_executor->Execute(
        context,
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, operations::KEY_ENCAPSULATE},
        encapsulate_request);
    ASSERT_TRUE(encapsulated.has_value());
    const auto encapsulated_secret_id = std::get<std::uint64_t>(encapsulated.value()[1]);
    auto encapsulated_secret =
        service->AcquireKeyForOperation(kClientId, encapsulated_secret_id, kProviderId, Permission::kDerive);
    ASSERT_TRUE(encapsulated_secret.has_value());
    EXPECT_EQ(encapsulated_secret.value()->GetHandle().algorithm.name, algorithm);

    const auto private_key = RegisterSource(key_management::KeyMaterialKind::kPrivateKey, Permission::kAgree, algorithm);
    const auto ciphertext = KemTestFactory::kCiphertext;
    common::RequestParameters decapsulate_request{
        algorithm,
        static_cast<std::uint64_t>(private_key),
        score::cpp::span<const std::uint8_t>{ciphertext.data(), ciphertext.size()}};
    auto decapsulated = key_executor->Execute(
        context,
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, operations::KEY_DECAPSULATE},
        decapsulate_request);
    ASSERT_TRUE(decapsulated.has_value());
    const auto decapsulated_secret_id = std::get<std::uint64_t>(decapsulated.value()[0]);
    auto decapsulated_secret =
        service->AcquireKeyForOperation(kClientId, decapsulated_secret_id, kProviderId, Permission::kDerive);
    ASSERT_TRUE(decapsulated_secret.has_value());
    EXPECT_EQ(decapsulated_secret.value()->GetHandle().algorithm.name, algorithm);
    EXPECT_EQ(factory->get_size_calls, 2U);
    EXPECT_EQ(factory->encapsulate_calls, 1U);
    EXPECT_EQ(factory->decapsulate_calls, 1U);
}

// ---------------------------------------------------------------------------
// KEM executor request validation
// ---------------------------------------------------------------------------

TEST_F(KeyManagementExecutorKemTest, KEMValidationRejectsWrongRoleMissingPermissionAndSmallOutputBuffer)
{
    const auto private_key = RegisterSource(key_management::KeyMaterialKind::kPrivateKey, Permission::kAgree);
    common::RequestParameters wrong_role{std::string_view{kAlgorithm}, static_cast<std::uint64_t>(private_key)};
    auto wrong_role_result = key_executor->Execute(
        context,
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, operations::KEY_GET_ENCAPSULATION_SIZE},
        wrong_role);
    ASSERT_FALSE(wrong_role_result.has_value());
    EXPECT_EQ(wrong_role_result.error(), Error::kInvalidArgument);

    const auto non_agree_public = RegisterSource(key_management::KeyMaterialKind::kPublicKey, Permission::kExport);
    common::RequestParameters missing_permission{std::string_view{kAlgorithm},
                                                 static_cast<std::uint64_t>(non_agree_public)};
    auto missing_permission_result = key_executor->Execute(
        context,
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, operations::KEY_GET_ENCAPSULATION_SIZE},
        missing_permission);
    ASSERT_FALSE(missing_permission_result.has_value());
    EXPECT_EQ(missing_permission_result.error(), Error::kKeyOperationNotPermitted);

    const auto public_key = RegisterSource(key_management::KeyMaterialKind::kPublicKey, Permission::kAgree);
    std::array<std::uint8_t, 3U> ciphertext_out{};
    common::RequestParameters small_output{
        std::string_view{kAlgorithm},
        static_cast<std::uint64_t>(public_key),
        score::cpp::span<std::uint8_t>{ciphertext_out.data(), ciphertext_out.size()}};
    auto small_output_result = key_executor->Execute(
        context, {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, operations::KEY_ENCAPSULATE}, small_output);
    ASSERT_FALSE(small_output_result.has_value());
    EXPECT_EQ(small_output_result.error(), Error::kInsufficientBufferSize);
    EXPECT_EQ(factory->encapsulate_calls, 0U);
}

// ---------------------------------------------------------------------------
// Key operation permissions
// ---------------------------------------------------------------------------

TEST_F(KeyManagementExecutorKemTest, PublicKeyPermissionsGovernEveryRequestedOperation)
{
    const Permission granted = Permission::kAgree | Permission::kExport | Permission::kVerify;
    const data_manager::DataNodeId key_id = RegisterSource(key_management::KeyMaterialKind::kPublicKey, granted);

    for (const Permission required :
         {Permission::kAgree, Permission::kExport, Permission::kVerify, Permission::kVerify | Permission::kExport})
    {
        const score::crypto::Expected<std::shared_ptr<key_management::KeyEntry>, Error> lease =
            service->AcquireKeyForOperation(kClientId, key_id, kProviderId, required);
        EXPECT_TRUE(lease.has_value());
    }
    for (const Permission required : {Permission::kEncrypt, Permission::kAgree | Permission::kEncrypt})
    {
        const score::crypto::Expected<std::shared_ptr<key_management::KeyEntry>, Error> lease =
            service->AcquireKeyForOperation(kClientId, key_id, kProviderId, required);
        ASSERT_FALSE(lease.has_value());
        EXPECT_EQ(lease.error(), Error::kKeyOperationNotPermitted);
    }
}

TEST_F(KeyManagementExecutorKemTest, UnspecifiedPublicKeyPermissionsRemainUnrestricted)
{
    key_management::ProviderKeyHandle handle{};
    handle.provider_id = kProviderId;
    handle.algorithm = *::score::crypto::GetAlgorithmDescriptor(kAlgorithm);
    handle.material_kind = key_management::KeyMaterialKind::kPublicKey;
    handle.is_asymmetric = true;
    handle.key_size = 32U;
    handle.permissions = Permission::kNone;
    const score::crypto::Expected<key_management::KeyDataNodeResult, Error> registered = service->RegisterKeyMaterial(
        {kClientId, context.context_node_id, kProviderId},
        std::make_shared<TestKeyHandler>(handle, std::make_shared<ReleaseState>()));
    ASSERT_TRUE(registered.has_value());

    for (const Permission required : {Permission::kAgree, Permission::kExport, Permission::kVerify})
    {
        const score::crypto::Expected<std::shared_ptr<key_management::KeyEntry>, Error> lease =
            service->AcquireKeyForOperation(kClientId, registered.value().node_id, kProviderId, required);
        EXPECT_TRUE(lease.has_value());
    }
}

TEST_F(KeyManagementExecutorKemTest, AsymmetricHandlesKeepPublicAndPrivateOperationPermissionsSeparate)
{
    key_management::ProviderKeyHandle handle{};
    handle.provider_id = kProviderId;
    handle.algorithm = *::score::crypto::GetAlgorithmDescriptor(kAlgorithm);
    handle.material_kind = key_management::KeyMaterialKind::kPrivateKey;
    handle.is_asymmetric = true;
    handle.key_size = 32U;
    handle.permissions = Permission::kSign | Permission::kDerive;
    handle.public_key_permissions =
        Permission::kVerify | Permission::kEncrypt | Permission::kWrap | Permission::kAgree | Permission::kExport;
    const score::crypto::Expected<key_management::KeyDataNodeResult, Error> registered = service->RegisterKeyMaterial(
        {kClientId, context.context_node_id, kProviderId},
        std::make_shared<TestKeyHandler>(handle, std::make_shared<ReleaseState>()));
    ASSERT_TRUE(registered.has_value());

    for (const Permission required :
         {Permission::kSign, Permission::kDerive, Permission::kVerify, Permission::kEncrypt, Permission::kWrap})
    {
        const score::crypto::Expected<std::shared_ptr<key_management::KeyEntry>, Error> lease =
            service->AcquireKeyForOperation(kClientId, registered.value().node_id, kProviderId, required);
        EXPECT_TRUE(lease.has_value());
    }
    for (const Permission required : {Permission::kAgree, Permission::kExport, Permission::kDecrypt})
    {
        const score::crypto::Expected<std::shared_ptr<key_management::KeyEntry>, Error> lease =
            service->AcquireKeyForOperation(kClientId, registered.value().node_id, kProviderId, required);
        ASSERT_FALSE(lease.has_value());
        EXPECT_EQ(lease.error(), Error::kKeyOperationNotPermitted);
    }
}

TEST_F(KeyManagementExecutorKemTest, SymmetricKeysAndSharedSecretsUseTheirOwnPermissions)
{
    for (const key_management::KeyMaterialKind kind :
         {key_management::KeyMaterialKind::kSymmetricKey, key_management::KeyMaterialKind::kSharedSecret})
    {
        key_management::ProviderKeyHandle handle{};
        handle.provider_id = kProviderId;
        handle.algorithm = *::score::crypto::GetAlgorithmDescriptor(kAlgorithm);
        handle.material_kind = kind;
        handle.key_size = 32U;
        handle.permissions = Permission::kDerive;
        const score::crypto::Expected<key_management::KeyDataNodeResult, Error> registered =
            service->RegisterKeyMaterial(
                {kClientId, context.context_node_id, kProviderId},
                std::make_shared<TestKeyHandler>(handle, std::make_shared<ReleaseState>()));
        ASSERT_TRUE(registered.has_value());

        {
            const score::crypto::Expected<std::shared_ptr<key_management::KeyEntry>, Error> lease =
                service->AcquireKeyForOperation(
                    kClientId, registered.value().node_id, kProviderId, Permission::kDerive);
            EXPECT_TRUE(lease.has_value());
        }
        for (const Permission required : {Permission::kAgree, Permission::kExport, Permission::kVerify})
        {
            const score::crypto::Expected<std::shared_ptr<key_management::KeyEntry>, Error> lease =
                service->AcquireKeyForOperation(kClientId, registered.value().node_id, kProviderId, required);
            ASSERT_FALSE(lease.has_value());
            EXPECT_EQ(lease.error(), Error::kKeyOperationNotPermitted);
        }
    }
}

// ---------------------------------------------------------------------------
// KEM source-key operation lifetime
// ---------------------------------------------------------------------------

TEST_F(KeyManagementExecutorKemTest, ResolvedEntryKeepsSourceAliveAfterItsNodeIsReleased)
{
    auto released = std::make_shared<ReleaseState>();
    auto registered = service->RegisterKeyMaterial(
        {kClientId, context.context_node_id, kProviderId},
        MakeKey(key_management::KeyMaterialKind::kPublicKey, Permission::kAgree, kAlgorithm, released));
    ASSERT_TRUE(registered.has_value());

    const auto source_id = registered.value().node_id;
    registered.value().key_node.reset();
    {
        auto entry = service->ResolveKeyForOperation(kClientId, source_id);
        ASSERT_TRUE(entry.has_value());
        ASSERT_TRUE(service->ReleaseKeyMaterial(kClientId, source_id).has_value());
        EXPECT_FALSE(released->released);
        EXPECT_EQ(entry.value()->GetHandle().material_kind, key_management::KeyMaterialKind::kPublicKey);
    }
    EXPECT_TRUE(released->released);
}

TEST_F(KeyManagementExecutorKemTest, AcquiringAnEntryDoesNotBlockAnotherAcquisition)
{
    const auto source_id = RegisterSource(key_management::KeyMaterialKind::kPublicKey, Permission::kAgree);
    auto entry = service->AcquireKeyForOperation(kClientId, source_id, kProviderId, Permission::kAgree);
    ASSERT_TRUE(entry.has_value());

    auto another_entry = std::async(std::launch::async, [&]() {
        return service->AcquireKeyForOperation(kClientId, source_id, kProviderId, Permission::kAgree);
    });
    const auto status = another_entry.wait_for(std::chrono::seconds{1});
    entry.value().reset();

    ASSERT_EQ(status, std::future_status::ready);
    ASSERT_TRUE(another_entry.get().has_value());
}

// ---------------------------------------------------------------------------
// Default KEM factory operation behavior
// ---------------------------------------------------------------------------

TEST(KeyManagementFactoryKemTest, DefaultKemHooksReturnUnsupported)
{
    key_management::IKeyFactory factory;
    const auto public_key = MakeKey(key_management::KeyMaterialKind::kPublicKey, Permission::kAgree);
    const auto private_key = MakeKey(key_management::KeyMaterialKind::kPrivateKey, Permission::kAgree);
    const std::array<std::uint8_t, 1U> ciphertext{{0x01U}};

    auto size = factory.GetEncapsulationCiphertextSize({*public_key, *::score::crypto::GetAlgorithmDescriptor(kAlgorithm)});
    auto encapsulate = factory.EncapsulateKey({*public_key, *::score::crypto::GetAlgorithmDescriptor(kAlgorithm)});
    auto decapsulate = factory.DecapsulateKey(
        {*private_key, *::score::crypto::GetAlgorithmDescriptor(kAlgorithm), score::cpp::span<const std::uint8_t>{ciphertext.data(), ciphertext.size()}});

    ASSERT_FALSE(size.has_value());
    ASSERT_FALSE(encapsulate.has_value());
    ASSERT_FALSE(decapsulate.has_value());
    EXPECT_EQ(size.error(), Error::kUnsupportedOperation);
    EXPECT_EQ(encapsulate.error(), Error::kUnsupportedOperation);
    EXPECT_EQ(decapsulate.error(), Error::kUnsupportedOperation);
}

class RecordingConnection final : public api::IConnection
{
  public:
    std::vector<control::ControlRequest> requests;
    std::vector<score::crypto::Expected<control::ControlResponse, score::crypto::CryptoErrorCode>> replies;
    std::function<void(const control::ControlRequest&)> on_request;

    score::crypto::Expected<control::ControlResponse, score::crypto::CryptoErrorCode> SendRequest(
        const control::ControlRequest& request) override
    {
        requests.push_back(request);
        if (on_request)
        {
            on_request(request);
        }
        if (!replies.empty())
        {
            auto response = std::move(replies.front());
            replies.erase(replies.begin());
            return response;
        }
        return Success(request.operation.operations.front().operationId, {});
    }

    control::DataNodeId GetConnectionNodeId() const override
    {
        return 1U;
    }

    static control::ControlResponse Success(const common::OperationIdentifier& operation,
                                            common::ResponseParameters parameters)
    {
        return control::ControlResponse{0U,
                                        control::OperationResponse{{control::SingleOperationResponse{
                                            operation, control::OPERATION_RESULT_SUCCESS, std::move(parameters)}}}};
    }
};

score::crypto::CryptoResourceId KeyId(std::uint64_t id)
{
    return {id, score::crypto::ResourceType::kKey, score::crypto::ResourcePersistence::kEphemeral, kProviderId};
}

// ---------------------------------------------------------------------------
// Key generation API IPC compatibility
// ---------------------------------------------------------------------------

TEST(KeyManagementContextTest, GenerateKeySendsItsParametersAndReturnsAnEphemeralGuard)
{
    auto connection = std::make_shared<RecordingConnection>();
    score::crypto::KeyManagementContextImpl context{connection, 44U};
    connection->replies.push_back(RecordingConnection::Success(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, operations::KEY_GENERATE},
        {std::uint64_t{81U}, kProviderId}));
    score::crypto::GenerateKeyParams params{};
    params.SetAlgorithm("ML-KEM-768").SetPermissions(Permission::kAgree);

    auto result = context.GenerateKey(params);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->Id().id, 81U);
    EXPECT_EQ(result->Id().type, score::crypto::ResourceType::kKey);
    EXPECT_EQ(result->Id().persistence, score::crypto::ResourcePersistence::kEphemeral);
    EXPECT_EQ(result->Id().primary_provider, kProviderId);
    ASSERT_EQ(connection->requests.size(), 1U);
    const auto& request = connection->requests.front();
    EXPECT_EQ(request.data_node_id, 44U);
    ASSERT_EQ(request.operation.operations.size(), 1U);
    const auto& operation = request.operation.operations.front();
    EXPECT_EQ(operation.operationId.operationActor, score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT);
    EXPECT_EQ(operation.operationId.operationAction, operations::KEY_GENERATE);
    ASSERT_EQ(operation.parameters.size(), 2U);
    EXPECT_EQ(std::get<std::string_view>(operation.parameters[0]), kAlgorithm);
    EXPECT_EQ(std::get<std::uint32_t>(operation.parameters[1]), static_cast<std::uint32_t>(Permission::kAgree));

    ASSERT_TRUE(result->Release().has_value());
    ASSERT_EQ(connection->requests.size(), 2U);
    const auto& release = connection->requests.back().operation.operations.front();
    EXPECT_EQ(release.operationId.operationAction, operations::KEY_RELEASE);
    EXPECT_EQ(std::get<std::uint64_t>(release.parameters.front()), 81U);
}

TEST(KeyManagementContextTest, GenerateKeySendsPublicKeyPermissionsOnlyWhenSpecified)
{
    auto connection = std::make_shared<RecordingConnection>();
    score::crypto::KeyManagementContextImpl context{connection, 44U};
    connection->replies.push_back(RecordingConnection::Success(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, operations::KEY_GENERATE},
        {std::uint64_t{81U}}));
    score::crypto::GenerateKeyParams params{};
    params.SetAlgorithm("ML-KEM-768").SetPublicKeyPermissions(Permission::kAgree);

    auto result = context.GenerateKey(params);

    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(connection->requests.size(), 1U);
    const auto& parameters = connection->requests.front().operation.operations.front().parameters;
    ASSERT_EQ(parameters.size(), 3U);
    EXPECT_EQ(std::get<std::uint32_t>(parameters[2]), static_cast<std::uint32_t>(Permission::kAgree));
}

TEST(KeyManagementContextTest, GenerateKeyKeepsTheProviderIdOptional)
{
    const std::vector<common::ResponseParameters> replies{{std::uint64_t{81U}},
                                                         {std::uint64_t{81U}, std::uint32_t{3U}}};
    for (const auto& parameters : replies)
    {
        auto connection = std::make_shared<RecordingConnection>();
        score::crypto::KeyManagementContextImpl context{connection, 44U};
        connection->replies.push_back(RecordingConnection::Success(
            {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, operations::KEY_GENERATE}, parameters));
        score::crypto::GenerateKeyParams params{};
        params.SetAlgorithm("ML-KEM-768");

        auto result = context.GenerateKey(params);

        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(result->Id().id, 81U);
        EXPECT_EQ(result->Id().primary_provider, score::crypto::CryptoResourceId{}.primary_provider);
    }
}

TEST(KeyManagementContextTest, GenerateKeyPreservesItsExistingResponseLayoutHandling)
{
    auto connection = std::make_shared<RecordingConnection>();
    score::crypto::KeyManagementContextImpl context{connection, 44U};
    auto response = RecordingConnection::Success(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, operations::KEY_GENERATE},
        {std::uint64_t{81U}, kProviderId, std::uint32_t{7U}});
    response.operation.operations.push_back(control::SingleOperationResponse{
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, operations::KEY_LOAD},
        control::OPERATION_RESULT_SUCCESS,
        {}});
    connection->replies.push_back(std::move(response));
    score::crypto::GenerateKeyParams params{};
    params.SetAlgorithm("ML-KEM-768");

    auto result = context.GenerateKey(params);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->Id().id, 81U);
    EXPECT_EQ(result->Id().primary_provider, kProviderId);
}

TEST(KeyManagementContextTest, GenerateKeyMapsTransportFailureToKeyGenerationFailed)
{
    auto connection = std::make_shared<RecordingConnection>();
    score::crypto::KeyManagementContextImpl context{connection, 44U};
    connection->replies.push_back(score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kConnectionFailed));
    score::crypto::GenerateKeyParams params{};
    params.SetAlgorithm("ML-KEM-768");

    auto result = context.GenerateKey(params);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::MakeError(score::crypto::CryptoErrorCode::kKeyGenerationFailed));
}

TEST(KeyManagementContextTest, GenerateKeyMapsDaemonFailureToKeyGenerationFailed)
{
    auto connection = std::make_shared<RecordingConnection>();
    score::crypto::KeyManagementContextImpl context{connection, 44U};
    auto response = RecordingConnection::Success(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, operations::KEY_GENERATE}, {});
    response.operation.operations.front().result =
        static_cast<control::OperationResult>(score::crypto::CryptoErrorCode::kUnsupportedAlgorithm);
    connection->replies.push_back(std::move(response));
    score::crypto::GenerateKeyParams params{};
    params.SetAlgorithm("ML-KEM-768");

    auto result = context.GenerateKey(params);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::MakeError(score::crypto::CryptoErrorCode::kKeyGenerationFailed));
}

TEST(KeyManagementContextTest, GenerateKeyRejectsMissingOrMistypedResourceIds)
{
    const std::vector<common::ResponseParameters> replies{{}, {std::uint32_t{81U}}};
    for (const auto& parameters : replies)
    {
        auto connection = std::make_shared<RecordingConnection>();
        score::crypto::KeyManagementContextImpl context{connection, 44U};
        connection->replies.push_back(RecordingConnection::Success(
            {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, operations::KEY_GENERATE}, parameters));
        score::crypto::GenerateKeyParams params{};
        params.SetAlgorithm("ML-KEM-768");

        auto result = context.GenerateKey(params);

        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error(), score::crypto::MakeError(score::crypto::CryptoErrorCode::kKeyGenerationFailed));
    }
}

TEST(KeyManagementContextTest, GenerateKeyRejectsWrongOperationResponses)
{
    auto connection = std::make_shared<RecordingConnection>();
    score::crypto::KeyManagementContextImpl context{connection, 44U};
    connection->replies.push_back(RecordingConnection::Success(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, operations::KEY_LOAD}, {std::uint64_t{81U}}));
    score::crypto::GenerateKeyParams params{};
    params.SetAlgorithm("ML-KEM-768");

    auto result = context.GenerateKey(params);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::MakeError(score::crypto::CryptoErrorCode::kKeyGenerationFailed));
}

TEST(KeyManagementContextTest, GenerateKeyHandlesAMissingConnection)
{
    score::crypto::KeyManagementContextImpl context{nullptr, 44U};
    score::crypto::GenerateKeyParams params{};
    params.SetAlgorithm("ML-KEM-768");

    auto result = context.GenerateKey(params);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::MakeError(score::crypto::CryptoErrorCode::kKeyGenerationFailed));
}

// ---------------------------------------------------------------------------
// KEM API parameter validation
// ---------------------------------------------------------------------------

TEST(KeyManagementContextKemTest, ValidatesTypedParamsBeforeSendingARequest)
{
    auto connection = std::make_shared<RecordingConnection>();
    score::crypto::KeyManagementContextImpl context{connection, 44U};
    score::crypto::EncapsulateKeyParams encapsulate{};
    score::crypto::DecapsulateKeyParams decapsulate{};

    EXPECT_FALSE(encapsulate.Validate().has_value());
    EXPECT_FALSE(decapsulate.Validate().has_value());
    EXPECT_FALSE(context.GetEncapsulationCiphertextSize(encapsulate).has_value());
    EXPECT_FALSE(context.DecapsulateKey(decapsulate).has_value());
    EXPECT_TRUE(connection->requests.empty());
}

// ---------------------------------------------------------------------------
// Key-material API IPC contracts
// ---------------------------------------------------------------------------

TEST(KeyManagementContextKemTest, MaterialOperationsUseTheirKeyManagementIpcContracts)
{
    auto connection = std::make_shared<RecordingConnection>();
    auto registry = std::make_shared<score::crypto::ShmRegionRegistry>(1024U);
    auto transcoder = std::make_shared<score::crypto::BufferShmTranscoder>(nullptr, registry);
    score::crypto::KeyManagementContextImpl context{connection, 44U, transcoder};
    const std::array<std::uint8_t, 3U> raw_key{{0x21U, 0x22U, 0x23U}};
    registry->Register({89U, reinterpret_cast<std::uintptr_t>(raw_key.data()), raw_key.size(), false});
    score::crypto::ImportKeyParams import{};
    import.algorithm = "ML-KEM-768";
    import.key_data = {raw_key.data(), raw_key.size()};
    import.format = score::crypto::FormatType::kRaw;
    import.permissions = Permission::kAgree;

    connection->replies.push_back(RecordingConnection::Success(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, operations::KEY_IMPORT},
        {static_cast<std::uint64_t>(81U), kProviderId}));
    auto imported = context.ImportKey(import);
    ASSERT_TRUE(imported.has_value());
    EXPECT_EQ(imported->Id().id, 81U);
    EXPECT_EQ(imported->Id().type, score::crypto::ResourceType::kKey);
    ASSERT_TRUE(imported->Release().has_value());

    connection->replies.push_back(RecordingConnection::Success(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, operations::KEY_GET_EXPORT_SIZE},
        {static_cast<std::uint64_t>(3U)}));
    auto size = context.GetExportKeySize(KeyId(81U), score::crypto::FormatType::kRaw);
    ASSERT_TRUE(size.has_value());
    EXPECT_EQ(size.value(), 3U);

    connection->replies.push_back(RecordingConnection::Success(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, operations::KEY_EXPORT},
        {static_cast<std::uint64_t>(raw_key.size())}));
    std::array<std::uint8_t, 3U> exported{};
    registry->Register({90U, reinterpret_cast<std::uintptr_t>(exported.data()), exported.size(), false});
    connection->on_request = [&](const control::ControlRequest& request) {
        const auto& operation = request.operation.operations[0];
        if (operation.operationId.operationAction == operations::KEY_EXPORT)
        {
            std::copy(raw_key.begin(), raw_key.end(), exported.begin());
        }
    };
    auto export_size = context.ExportKey(KeyId(81U), {exported.data(), exported.size()}, score::crypto::FormatType::kRaw);
    ASSERT_TRUE(export_size.has_value());
    EXPECT_EQ(export_size.value(), exported.size());
    EXPECT_EQ(exported, raw_key);
    connection->on_request = {};

    ASSERT_GE(connection->requests.size(), 4U);
    EXPECT_EQ(connection->requests[0].operation.operations[0].operationId.operationAction, operations::KEY_IMPORT);
    EXPECT_EQ(std::get<common::DataShm>(connection->requests[0].operation.operations[0].parameters[3]).direction,
              common::ShmDirection::In);
    EXPECT_EQ(connection->requests[2].operation.operations[0].operationId.operationAction, operations::KEY_GET_EXPORT_SIZE);
    EXPECT_EQ(connection->requests[3].operation.operations[0].operationId.operationAction, operations::KEY_EXPORT);
    EXPECT_EQ(std::get<common::DataShm>(connection->requests[3].operation.operations[0].parameters[2]).direction,
              common::ShmDirection::InOut);
}

// ---------------------------------------------------------------------------
// KEM API IPC contracts and shared-secret guards
// ---------------------------------------------------------------------------

TEST(KeyManagementContextKemTest, UsesDedicatedOperationsAndReturnsOnlyGuardsForSecrets)
{
    auto connection = std::make_shared<RecordingConnection>();
    auto registry = std::make_shared<score::crypto::ShmRegionRegistry>(1024U);
    auto transcoder = std::make_shared<score::crypto::BufferShmTranscoder>(nullptr, registry);
    score::crypto::KeyManagementContextImpl context{connection, 44U, transcoder};
    score::crypto::EncapsulateKeyParams encapsulate{};
    encapsulate.SetPeerPublicKey(KeyId(20U)).SetAlgorithm(score::crypto::AlgorithmId{kAlgorithm});
    const std::array<std::uint8_t, 4U> ciphertext{{0U, 0U, 0U, 0U}};
    registry->Register({89U, reinterpret_cast<std::uintptr_t>(ciphertext.data()), ciphertext.size(), false});
    score::crypto::DecapsulateKeyParams decapsulate{};
    decapsulate.SetPrivateKey(KeyId(21U))
        .SetAlgorithm(score::crypto::AlgorithmId{kAlgorithm})
        .SetCiphertext({ciphertext.data(), ciphertext.size()});

    connection->replies.push_back(RecordingConnection::Success(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, operations::KEY_GET_ENCAPSULATION_SIZE}, {static_cast<std::uint64_t>(4U)}));
    auto size = context.GetEncapsulationCiphertextSize(encapsulate);
    ASSERT_TRUE(size.has_value());
    EXPECT_EQ(size.value(), 4U);

    connection->replies.push_back(RecordingConnection::Success(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, operations::KEY_ENCAPSULATE},
        {static_cast<std::uint64_t>(4U), static_cast<std::uint64_t>(71U), kProviderId}));
    std::array<std::uint8_t, 4U> output{};
    registry->Register({90U, reinterpret_cast<std::uintptr_t>(output.data()), output.size(), false});
    connection->on_request = [&](const control::ControlRequest& request) {
        if (request.operation.operations[0].operationId.operationAction == operations::KEY_ENCAPSULATE)
        {
            output = {{0x10U, 0x11U, 0x12U, 0x13U}};
        }
    };
    auto encapsulated = context.EncapsulateKey(encapsulate, {output.data(), output.size()});
    ASSERT_TRUE(encapsulated.has_value());
    EXPECT_EQ(encapsulated->ciphertext_size, output.size());
    EXPECT_EQ(output, (std::array<std::uint8_t, 4U>{{0x10U, 0x11U, 0x12U, 0x13U}}));
    connection->on_request = {};
    EXPECT_EQ(encapsulated->shared_secret.Id().id, 71U);
    EXPECT_EQ(encapsulated->shared_secret.Id().type, score::crypto::ResourceType::kSharedSecret);
    EXPECT_EQ(encapsulated->shared_secret.Id().persistence, score::crypto::ResourcePersistence::kEphemeral);
    EXPECT_EQ(encapsulated->shared_secret.Id().primary_provider, kProviderId);

    score::crypto::DeriveKeyParams derive{};
    derive.SetSourceKey(encapsulated->shared_secret)
        .SetDerivedKeyAlgorithm("AES-256")
        .SetKdf(score::crypto::KdfParameters{}.SetKdfAlgorithm("HKDF-SHA256"));
    EXPECT_TRUE(derive.Validate().has_value());
    ASSERT_TRUE(encapsulated->shared_secret.Release().has_value());

    connection->replies.push_back(RecordingConnection::Success(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, operations::KEY_DECAPSULATE}, {static_cast<std::uint64_t>(72U), kProviderId}));
    auto decapsulated = context.DecapsulateKey(decapsulate);
    ASSERT_TRUE(decapsulated.has_value());
    EXPECT_EQ(decapsulated->Id().id, 72U);
    EXPECT_EQ(decapsulated->Id().type, score::crypto::ResourceType::kSharedSecret);
    EXPECT_EQ(decapsulated->Id().persistence, score::crypto::ResourcePersistence::kEphemeral);
    EXPECT_EQ(decapsulated->Id().primary_provider, kProviderId);
    derive.SetSourceKey(decapsulated.value());
    EXPECT_TRUE(derive.Validate().has_value());
    ASSERT_TRUE(decapsulated->Release().has_value());

    ASSERT_GE(connection->requests.size(), 5U);
    EXPECT_EQ(connection->requests[0].operation.operations[0].operationId.operationAction,
              operations::KEY_GET_ENCAPSULATION_SIZE);
    EXPECT_EQ(connection->requests[1].operation.operations[0].operationId.operationAction, operations::KEY_ENCAPSULATE);
    EXPECT_EQ(connection->requests[3].operation.operations[0].operationId.operationAction, operations::KEY_DECAPSULATE);
    EXPECT_EQ(connection->requests[1].operation.operations[0].parameters.size(), 3U);
    EXPECT_EQ(connection->requests[3].operation.operations[0].parameters.size(), 3U);
    EXPECT_EQ(std::get<common::DataShm>(connection->requests[1].operation.operations[0].parameters[2]).direction,
              common::ShmDirection::InOut);
    EXPECT_EQ(std::get<common::DataShm>(connection->requests[3].operation.operations[0].parameters[2]).direction,
              common::ShmDirection::In);
    for (const std::size_t index : {2U, 4U})
    {
        const control::ControlRequest& release_request = connection->requests[index];
        EXPECT_EQ(release_request.data_node_id, 44U);
        const control::SingleOperationRequest& release = release_request.operation.operations.front();
        EXPECT_EQ(release.operationId.operationActor, score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT);
        EXPECT_EQ(release.operationId.operationAction, operations::KEY_RELEASE);
        ASSERT_EQ(release.parameters.size(), 1U);
        EXPECT_EQ(std::get<std::uint64_t>(release.parameters.front()), index == 2U ? 71U : 72U);
    }
}

// ---------------------------------------------------------------------------
// Shared-secret resource classification and permitted API uses
// ---------------------------------------------------------------------------

TEST(CryptoResourceIdTest, DefaultsToUnassignedResourceId)
{
    const score::crypto::CryptoResourceId resource{};
    EXPECT_EQ(resource.id, score::crypto::kInvalidCryptoResourceId);
    EXPECT_EQ(score::crypto::kInvalidCryptoResourceId, std::uint64_t{0U});
}

TEST(CryptoResourceTypeTest, SharedSecretPreservesExistingResourceTypeValues)
{
    using Type = score::crypto::ResourceType;
    EXPECT_EQ(static_cast<std::uint8_t>(Type::kProvider), 0U);
    EXPECT_EQ(static_cast<std::uint8_t>(Type::kKeySlot), 1U);
    EXPECT_EQ(static_cast<std::uint8_t>(Type::kCertSlot), 2U);
    EXPECT_EQ(static_cast<std::uint8_t>(Type::kCertificateTrustStore), 3U);
    EXPECT_EQ(static_cast<std::uint8_t>(Type::kKey), 4U);
    EXPECT_EQ(static_cast<std::uint8_t>(Type::kCertificate), 5U);
    EXPECT_EQ(static_cast<std::uint8_t>(Type::kSecureObject), 6U);
    EXPECT_EQ(static_cast<std::uint8_t>(Type::kDataObject), 7U);
    EXPECT_EQ(static_cast<std::uint8_t>(Type::kSharedSecret), 8U);
}

TEST(KeyDerivationParamsTest, AcceptsKeysAndSharedSecretsAsSources)
{
    for (const score::crypto::ResourceType type :
         {score::crypto::ResourceType::kKey, score::crypto::ResourceType::kSharedSecret})
    {
        score::crypto::CryptoResourceId source = KeyId(71U);
        source.type = type;
        score::crypto::DeriveKeyParams params{};
        params.SetSourceKey(source)
            .SetDerivedKeyAlgorithm("AES-256")
            .SetKdf(score::crypto::KdfParameters{}.SetKdfAlgorithm("HKDF-SHA256"));

        const score::Result<std::monostate> valid = params.Validate();
        EXPECT_TRUE(valid.has_value());

        source.id = score::crypto::kInvalidCryptoResourceId;
        params.SetSourceKey(source);
        const score::Result<std::monostate> missing_source = params.Validate();
        ASSERT_FALSE(missing_source.has_value());
        EXPECT_EQ(missing_source.error(), score::crypto::MakeError(score::crypto::CryptoErrorCode::kInvalidArgument));
    }
}

TEST(KeyDerivationParamsTest, RejectsOtherResourceTypes)
{
    using Type = score::crypto::ResourceType;
    for (const Type type : {Type::kProvider, Type::kKeySlot, Type::kCertSlot, Type::kCertificateTrustStore,
                            Type::kCertificate, Type::kSecureObject, Type::kDataObject})
    {
        score::crypto::CryptoResourceId source = KeyId(71U);
        source.type = type;
        score::crypto::DeriveKeyParams params{};
        params.SetSourceKey(source).SetKdf(score::crypto::KdfParameters{}.SetKdfAlgorithm("HKDF-SHA256"));

        const score::Result<std::monostate> valid = params.Validate();
        ASSERT_FALSE(valid.has_value());
        EXPECT_EQ(valid.error(), score::crypto::MakeError(score::crypto::CryptoErrorCode::kInvalidArgument));
    }
}

TEST(KeyDerivationParamsTest, SharedSecretValidationPreservesKdfErrors)
{
    score::crypto::CryptoResourceId source = KeyId(71U);
    source.type = score::crypto::ResourceType::kSharedSecret;
    score::crypto::DeriveKeyParams params{};
    params.SetSourceKey(source);
    const score::Result<std::monostate> missing_kdf = params.Validate();
    ASSERT_FALSE(missing_kdf.has_value());
    EXPECT_EQ(missing_kdf.error(), score::crypto::MakeError(score::crypto::CryptoErrorCode::kInvalidArgument));

    const std::array<std::uint8_t, score::crypto::KdfParameters::kMaxSaltLength + 1U> salt{};
    score::crypto::KdfParameters kdf{};
    kdf.SetKdfAlgorithm("HKDF-SHA256").SetSalt(salt.data(), salt.size());
    params.SetKdf(kdf);
    const score::Result<std::monostate> truncated_kdf = params.Validate();
    ASSERT_FALSE(truncated_kdf.has_value());
    EXPECT_EQ(truncated_kdf.error(), score::crypto::MakeError(score::crypto::CryptoErrorCode::kParamTruncated));
}

TEST(KeyManagementContextKemTest, RejectsSharedSecretsAsKemInputKeysOrExportableKeys)
{
    const std::shared_ptr<RecordingConnection> connection = std::make_shared<RecordingConnection>();
    score::crypto::KeyManagementContextImpl context{connection, 44U};
    score::crypto::CryptoResourceId secret = KeyId(71U);
    secret.type = score::crypto::ResourceType::kSharedSecret;
    score::crypto::EncapsulateKeyParams encapsulate{};
    encapsulate.SetPeerPublicKey(secret).SetAlgorithm(score::crypto::AlgorithmId{kAlgorithm});
    std::array<std::uint8_t, 4U> output{};
    score::crypto::DecapsulateKeyParams decapsulate{};
    decapsulate.SetPrivateKey(secret)
        .SetAlgorithm(score::crypto::AlgorithmId{kAlgorithm})
        .SetCiphertext({output.data(), output.size()});

    const score::Result<std::size_t> size = context.GetEncapsulationCiphertextSize(encapsulate);
    const score::Result<score::crypto::EncapsulationResult> encapsulated =
        context.EncapsulateKey(encapsulate, {output.data(), output.size()});
    const score::Result<score::crypto::CryptoResourceGuard> decapsulated = context.DecapsulateKey(decapsulate);
    const score::Result<std::size_t> export_size = context.GetExportKeySize(secret, score::crypto::FormatType::kRaw);
    const score::Result<std::size_t> exported =
        context.ExportKey(secret, {output.data(), output.size()}, score::crypto::FormatType::kRaw);

    ASSERT_FALSE(size.has_value());
    ASSERT_FALSE(encapsulated.has_value());
    ASSERT_FALSE(decapsulated.has_value());
    ASSERT_FALSE(export_size.has_value());
    ASSERT_FALSE(exported.has_value());
    const score::result::Error invalid_argument =
        score::crypto::MakeError(score::crypto::CryptoErrorCode::kInvalidArgument);
    EXPECT_EQ(size.error(), invalid_argument);
    EXPECT_EQ(encapsulated.error(), invalid_argument);
    EXPECT_EQ(decapsulated.error(), invalid_argument);
    EXPECT_EQ(export_size.error(), invalid_argument);
    EXPECT_EQ(exported.error(), invalid_argument);
    EXPECT_TRUE(connection->requests.empty());
}

TEST(KeyManagementContextKemTest, SharedSecretGuardDestructionSendsKeyRelease)
{
    const std::shared_ptr<RecordingConnection> connection = std::make_shared<RecordingConnection>();
    const std::shared_ptr<score::crypto::ShmRegionRegistry> registry =
        std::make_shared<score::crypto::ShmRegionRegistry>(1024U);
    const std::shared_ptr<score::crypto::BufferShmTranscoder> transcoder =
        std::make_shared<score::crypto::BufferShmTranscoder>(nullptr, registry);
    score::crypto::KeyManagementContextImpl context{connection, 44U, transcoder};
    const std::array<std::uint8_t, 4U> ciphertext{};
    registry->Register({89U, reinterpret_cast<std::uintptr_t>(ciphertext.data()), ciphertext.size(), false});
    score::crypto::DecapsulateKeyParams params{};
    params.SetPrivateKey(KeyId(21U))
        .SetAlgorithm(score::crypto::AlgorithmId{kAlgorithm})
        .SetCiphertext({ciphertext.data(), ciphertext.size()});
    connection->replies.push_back(RecordingConnection::Success(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, operations::KEY_DECAPSULATE},
        {std::uint64_t{72U}, kProviderId}));
    {
        const score::Result<score::crypto::CryptoResourceGuard> secret = context.DecapsulateKey(params);
        ASSERT_TRUE(secret.has_value());
        EXPECT_EQ(secret->Id().type, score::crypto::ResourceType::kSharedSecret);
        ASSERT_EQ(connection->requests.size(), 1U);
    }

    ASSERT_EQ(connection->requests.size(), 2U);
    const control::ControlRequest& request = connection->requests.back();
    EXPECT_EQ(request.data_node_id, 44U);
    const control::SingleOperationRequest& release = request.operation.operations.front();
    EXPECT_EQ(release.operationId.operationActor, score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT);
    EXPECT_EQ(release.operationId.operationAction, operations::KEY_RELEASE);
    ASSERT_EQ(release.parameters.size(), 1U);
    EXPECT_EQ(std::get<std::uint64_t>(release.parameters.front()), 72U);
}

// ---------------------------------------------------------------------------
// KEM parameter-set test instantiation
// ---------------------------------------------------------------------------

// Run the parameter-set dispatch test for every standardized ML-KEM variant.
INSTANTIATE_TEST_SUITE_P(AllStandardKemParameterSets,
                         KeyManagementExecutorKemVariantTest,
                         ::testing::Values(kKemAlgorithms[0], kKemAlgorithms[1], kKemAlgorithms[2]));

}  // namespace

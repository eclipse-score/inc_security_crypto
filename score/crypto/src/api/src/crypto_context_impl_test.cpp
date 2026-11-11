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

#include "score/crypto/src/api/src/crypto_context_impl.hpp"

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/config/cipher_context_config.hpp"
#include "score/crypto/src/api/config/hash_context_config.hpp"
#include "score/crypto/src/api/config/key_management_context_config.hpp"
#include "score/crypto/src/api/config/mac_context_config.hpp"
#include "score/crypto/src/api/config/random_context_config.hpp"
#include "score/crypto/src/api/config/sign_context_config.hpp"
#include "score/crypto/src/api/config/verify_signature_context_config.hpp"
#include "score/crypto/src/api/contexts/i_cipher_context.hpp"
#include "score/crypto/src/api/contexts/i_hash_context.hpp"
#include "score/crypto/src/api/contexts/i_key_management_context.hpp"
#include "score/crypto/src/api/contexts/i_mac_context.hpp"
#include "score/crypto/src/api/contexts/i_random_context.hpp"
#include "score/crypto/src/api/contexts/i_sign_context.hpp"
#include "score/crypto/src/api/contexts/i_verify_signature_context.hpp"
#include "score/crypto/src/api/control_plane/i_connection.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace score::crypto
{
namespace
{

namespace protocol = daemon::control_plane::protocol;

class ErrorConnection final : public api::control_plane::IConnection
{
  public:
    explicit ErrorConnection(const CryptoErrorCode error_code) : m_error_code{error_code} {}

    Expected<protocol::ControlResponse, CryptoErrorCode> SendRequest(const protocol::ControlRequest& request) override
    {
        ++m_request_count;
        m_last_request = request;
        protocol::ControlResponse response{};
        response.operation.operations.push_back(protocol::SingleOperationResponse{
            daemon::mediator::operations::CreateContext(), static_cast<protocol::OperationResult>(m_error_code), {}});
        return response;
    }

    protocol::DataNodeId GetConnectionNodeId() const override
    {
        return 1U;
    }

    std::size_t GetRequestCount() const noexcept
    {
        return m_request_count;
    }

    /// The CTX_CREATE provider slot (param[2]) of the last request.
    const daemon::common::RequestParameter& ProviderSlot() const
    {
        EXPECT_TRUE(m_last_request.has_value());
        return m_last_request->operation.operations.front().parameters.at(2U);
    }

  private:
    CryptoErrorCode m_error_code;
    std::size_t m_request_count{0U};
    std::optional<protocol::ControlRequest> m_last_request{};
};

TEST(CryptoContextImplTest, PreservesHashContextCreationErrorFromDaemon)
{
    auto connection = std::make_shared<ErrorConnection>(CryptoErrorCode::kUnsupportedAlgorithm);
    CryptoContextImpl context{connection, nullptr};

    HashContextConfig config;
    config.SetAlgorithm("UNSUPPORTED_ALGORITHM");
    const auto result = context.CreateHashContext(config);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(*result.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kUnsupportedAlgorithm));
}

CryptoResourceId ProviderHandle(std::uint64_t id = 42U)
{
    CryptoResourceId handle{};
    handle.id = id;
    handle.type = ResourceType::kProvider;
    handle.persistence = ResourcePersistence::kPersistent;
    handle.primary_provider = 0xFFFFU;
    return handle;
}

/// Calls one context factory with the given provider settings.
using CreateWith = std::function<void(CryptoContextImpl&, std::optional<CryptoResourceId>, ProviderType)>;

/// Applies the provider settings and, for a keyed context, a key, then creates the context.
template <typename Config, typename Create>
CreateWith Factory(Create create, bool keyed = false)
{
    return [create, keyed](CryptoContextImpl& context, std::optional<CryptoResourceId> provider, ProviderType type) {
        Config config{};
        config.algorithm = "ALG";
        config.provider = provider;
        config.provider_type = type;
        if constexpr (std::is_same_v<decltype(Config::key), CryptoResourceId>)
        {
            if (keyed)
            {
                config.key.id = 7U;
                config.key.type = ResourceType::kKeySlot;
            }
        }
        (void)create(context, config);
    };
}

/// Every context factory that takes a provider.
std::vector<std::pair<std::string, CreateWith>> AllFactories()
{
    return {
        {"Hash",
         [](CryptoContextImpl& c, std::optional<CryptoResourceId> p, ProviderType t) {
             HashContextConfig config{};
             config.algorithm = "SHA256";
             config.provider = p;
             config.provider_type = t;
             (void)c.CreateHashContext(config);
         }},
        {"Mac",
         Factory<MacContextConfig>(
             [](auto& c, const auto& cfg) {
                 return c.CreateMacContext(cfg);
             },
             true)},
        {"KeyManagement",
         [](CryptoContextImpl& c, std::optional<CryptoResourceId> p, ProviderType t) {
             KeyManagementContextConfig config{};
             config.provider = p;
             config.provider_type = t;
             (void)c.CreateKeyManagementContext(config);
         }},
        {"Cipher",
         Factory<CipherContextConfig>(
             [](auto& c, const auto& cfg) {
                 return c.CreateCipherContext(cfg);
             },
             true)},
        {"Sign",
         Factory<SignContextConfig>(
             [](auto& c, const auto& cfg) {
                 return c.CreateSignContext(cfg);
             },
             true)},
        {"Verify",
         Factory<VerifySignatureContextConfig>(
             [](auto& c, const auto& cfg) {
                 return c.CreateVerifySignatureContext(cfg);
             },
             true)},
        {"Random",
         [](CryptoContextImpl& c, std::optional<CryptoResourceId> p, ProviderType t) {
             RandomContextConfig config{};
             config.provider = p;
             config.provider_type = t;
             (void)c.CreateRandomContext(config);
         }},
    };
}

TEST(CryptoContextImplTest, ProviderHandleTakesTheProviderSlotForEveryContextType)
{
    // A provider resource wins over provider_type and is sent as the uint64
    // handle, which pins the context to that provider on the daemon side.
    for (const auto& [name, create] : AllFactories())
    {
        auto connection = std::make_shared<ErrorConnection>(CryptoErrorCode::kInternalError);
        CryptoContextImpl context{connection, nullptr};

        create(context, ProviderHandle(42U), ProviderType::kHardwarePreferred);

        ASSERT_EQ(connection->GetRequestCount(), 1U) << name;
        const auto* handle = std::get_if<std::uint64_t>(&connection->ProviderSlot());
        ASSERT_NE(handle, nullptr) << name;
        EXPECT_EQ(*handle, 42U) << name;
    }
}

TEST(CryptoContextImplTest, ProviderTypeStillTakesTheProviderSlotWithoutAHandle)
{
    for (const auto& [name, create] : AllFactories())
    {
        auto connection = std::make_shared<ErrorConnection>(CryptoErrorCode::kInternalError);
        CryptoContextImpl context{connection, nullptr};

        create(context, std::nullopt, ProviderType::kHardware);

        ASSERT_EQ(connection->GetRequestCount(), 1U) << name;
        const auto* type = std::get_if<std::uint8_t>(&connection->ProviderSlot());
        ASSERT_NE(type, nullptr) << name;
        EXPECT_EQ(*type, 1U) << name;
    }
}

TEST(CryptoContextImplTest, RejectsProviderThatIsNotAResolvedProviderResource)
{
    CryptoResourceId key_slot = ProviderHandle(42U);
    key_slot.type = ResourceType::kKeySlot;
    const CryptoResourceId unresolved = ProviderHandle(0U);

    for (const auto& [name, create] : AllFactories())
    {
        for (const auto& provider : {key_slot, unresolved})
        {
            auto connection = std::make_shared<ErrorConnection>(CryptoErrorCode::kInternalError);
            CryptoContextImpl context{connection, nullptr};

            create(context, provider, ProviderType::kDefault);

            EXPECT_EQ(connection->GetRequestCount(), 0U) << name << "/" << static_cast<int>(provider.type);
        }
    }
}

TEST(CryptoContextImplTest, ReportsNonProviderResourceAsInvalidResourceType)
{
    auto connection = std::make_shared<ErrorConnection>(CryptoErrorCode::kInternalError);
    CryptoContextImpl context{connection, nullptr};
    CryptoResourceId key_slot = ProviderHandle(42U);
    key_slot.type = ResourceType::kKeySlot;

    HashContextConfig config;
    config.SetAlgorithm("SHA256").SetProvider(key_slot);
    const auto result = context.CreateHashContext(config);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(*result.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kInvalidResourceType));
    EXPECT_EQ(connection->GetRequestCount(), 0U);
}

TEST(CryptoContextImplTest, ForwardsTheDaemonVerdictOnAProviderHandle)
{
    // E.g. the selected provider cannot serve the request: the daemon's own
    // code reaches the caller; the client does not retry elsewhere.
    auto connection = std::make_shared<ErrorConnection>(CryptoErrorCode::kCrossProviderIncompatible);
    CryptoContextImpl context{connection, nullptr};

    MacContextConfig config;
    config.SetAlgorithm("HMAC-SHA256").SetProvider(ProviderHandle());
    config.key.id = 7U;
    config.key.type = ResourceType::kKeySlot;
    const auto result = context.CreateMacContext(config);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(*result.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kCrossProviderIncompatible));
    EXPECT_EQ(connection->GetRequestCount(), 1U);
}

}  // namespace
}  // namespace score::crypto

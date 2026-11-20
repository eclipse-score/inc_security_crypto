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

#include "score/crypto/src/daemon/cert_management/cert_management_module.hpp"
#include "score/crypto/src/daemon/common/context/context_types.hpp"
#include "score/crypto/src/daemon/common/context/i_mediator_registrar.hpp"
#include "score/crypto/src/daemon/config/inc/config.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/data_manager/data_manager.hpp"
#include "score/crypto/src/daemon/key_management/key_management_module.hpp"
#include "score/crypto/src/daemon/mediator/mediator_factory.hpp"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"
#include "score/crypto/src/daemon/provider/provider_manager.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/provider_openssl.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

namespace cert_management = score::crypto::daemon::cert_management;
namespace common = score::crypto::daemon::common;
namespace config = score::crypto::daemon::config;
namespace control_plane = score::crypto::daemon::control_plane;
namespace data_manager = score::crypto::daemon::data_manager;
namespace key_management = score::crypto::daemon::key_management;
namespace mediator = score::crypto::daemon::mediator;
namespace openssl = score::crypto::daemon::provider::score_provider::openssl;
namespace provider = score::crypto::daemon::provider;

constexpr std::uint64_t kClient = 7U;

/// Builds the daemon's real key and certificate modules, registers them through the same factory the daemon
/// uses, and sends CTX_CREATE requests through the mediator.
class CertContextMediatorTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        m_data_manager = std::make_shared<data_manager::DataManager>();

        m_provider_manager = std::make_shared<provider::ProviderManager>(config::ProviderInitConfig{});
        auto openssl_provider = std::make_shared<openssl::OpenSSL>();
        ASSERT_TRUE(
            m_provider_manager->RegisterProvider("OPENSSL", openssl_provider, common::CryptoProviderType::SOFTWARE));
        ASSERT_TRUE(m_provider_manager->Initialize());

        const config::KeyConfig key_config{};
        auto key_module = key_management::KeyManagementModule::Create(m_data_manager, m_provider_manager, key_config);
        ASSERT_NE(key_module, nullptr);

        const config::CertificateConfig certificate_config{};
        auto cert_module =
            cert_management::CertManagementModule::Create(m_data_manager, m_provider_manager, certificate_config);
        ASSERT_NE(cert_module, nullptr);

        const std::vector<common::IMediatorRegistrar::Sptr> registrars{key_module, cert_module};
        auto mediator_result =
            mediator::MediatorFactory::Create(m_data_manager, m_provider_manager, key_module->GetService(), registrars);
        ASSERT_TRUE(mediator_result.has_value());
        m_mediator = std::move(mediator_result).value();

        auto connection =
            m_data_manager->addNode(kClient, std::make_shared<data_manager::DataNode>(/*exclusiveAccess=*/false));
        ASSERT_TRUE(connection.has_value());
        m_connection_id = connection.value();
    }

    /// Sends one CTX_CREATE for a context type that takes no algorithm and returns the single operation response.
    control_plane::protocol::SingleOperationResponse CreateContext(const std::string_view context_type)
    {
        control_plane::ControlRequest request{};
        request.request_id = 1U;
        request.client_id = kClient;
        request.data_node_id = m_connection_id;

        control_plane::protocol::SingleOperationRequest operation{};
        operation.operationId = mediator::operations::CreateContext();
        operation.parameters = common::RequestParameters{context_type, std::string_view{""}};
        request.operations.push_back(std::move(operation));

        auto responses = m_mediator->processRequest(request).operations;
        EXPECT_EQ(responses.size(), 1U);
        return responses.at(0U);
    }

    std::shared_ptr<data_manager::DataManager> m_data_manager;
    std::shared_ptr<provider::ProviderManager> m_provider_manager;
    std::shared_ptr<mediator::IMediator> m_mediator;
    data_manager::DataNodeId m_connection_id{};
};

TEST_F(CertContextMediatorTest, CertManagementContextIsCreatedThroughTheMediator)
{
    const auto response = CreateContext(common::context_types::kCertManagement);

    ASSERT_EQ(response.result, control_plane::protocol::OPERATION_RESULT_SUCCESS);
    EXPECT_TRUE(response.getParameter<std::uint64_t>(0U).has_value());
}

TEST_F(CertContextMediatorTest, CertVerificationContextIsCreatedThroughTheMediator)
{
    const auto response = CreateContext(common::context_types::kCertVerification);

    ASSERT_EQ(response.result, control_plane::protocol::OPERATION_RESULT_SUCCESS);
    EXPECT_TRUE(response.getParameter<std::uint64_t>(0U).has_value());
}

}  // namespace

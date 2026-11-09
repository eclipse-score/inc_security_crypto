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

#include "score/crypto/src/daemon/mediator/mediator_factory.hpp"

#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/config/inc/config.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"
#include "score/crypto/src/daemon/mediator/src/mediator_test_doubles.hpp"
#include "score/crypto/src/daemon/provider/provider_manager.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <vector>

namespace score::crypto::daemon::mediator
{
namespace
{

using common::DaemonErrorCode;
using test_doubles::RecordingDataManager;
using test_doubles::StubMediatorQuery;
using test_doubles::StubRegistrar;

constexpr std::uint64_t kClient = 7U;
constexpr common::OperationAction kQueryAction = 100U;

class MediatorFactoryTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        m_data_manager = std::make_shared<RecordingDataManager>();
        m_provider_manager = std::make_shared<provider::ProviderManager>(config::ProviderInitConfig{});
    }

    Expected<std::shared_ptr<IMediator>, DaemonErrorCode> Create(
        const std::vector<common::IMediatorRegistrar::Sptr>& registrars)
    {
        return MediatorFactory::Create(m_data_manager, m_provider_manager, nullptr, registrars);
    }

    // Sends one mediator-addressed operation and returns its result.
    static control_plane::protocol::OperationResult Send(IMediator& mediator, const common::OperationAction action)
    {
        control_plane::ControlRequest request{};
        request.request_id = 1U;
        request.client_id = kClient;
        request.data_node_id = 1U;
        control_plane::protocol::SingleOperationRequest operation{};
        operation.operationId = control_plane::protocol::OperationIdentifier{
            .operationActor = common::actors::OP_ACTOR_MEDIATOR, .operationAction = action};
        request.operation.operations.push_back(std::move(operation));

        const auto response = mediator.processRequest(request);
        return response.operation.operations.at(0U).result;
    }

    std::shared_ptr<RecordingDataManager> m_data_manager;
    provider::ProviderManager::Sptr m_provider_manager;
};

TEST_F(MediatorFactoryTest, CreatesAMediatorWithoutRegistrars)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__registration");
    RecordProperty("Description", "A mediator can be created with no registrars.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto mediator = Create({});

    EXPECT_TRUE(mediator.has_value());
}

TEST_F(MediatorFactoryTest, RegisteredQueryServesItsOperationCode)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__registration");
    RecordProperty("Description",
                   "A query registered through a registrar serves its operation code on the created mediator.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    auto query = std::make_shared<StubMediatorQuery>(42U);
    const auto registrar = std::make_shared<StubRegistrar>([&query](common::MediatorRegistries& registries) {
        return registries.mediator_queries.Register(kQueryAction, query);
    });

    const auto mediator = Create({registrar});

    ASSERT_TRUE(mediator.has_value());
    EXPECT_EQ(Send(*mediator.value(), kQueryAction), control_plane::protocol::OPERATION_RESULT_SUCCESS);
    EXPECT_EQ(query->Calls(), 1);
}

TEST_F(MediatorFactoryTest, EveryRegistrarIsCalledOnce)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__registration");
    RecordProperty("Description", "Each registrar is called exactly once while the mediator is created.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto first = std::make_shared<StubRegistrar>([](common::MediatorRegistries&) {
        return true;
    });
    const auto second = std::make_shared<StubRegistrar>([](common::MediatorRegistries&) {
        return true;
    });

    const auto mediator = Create({first, second});

    ASSERT_TRUE(mediator.has_value());
    EXPECT_EQ(first->Calls(), 1);
    EXPECT_EQ(second->Calls(), 1);
}

TEST_F(MediatorFactoryTest, RejectedRegistrationFailsCreation)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__registration");
    RecordProperty("Description",
                   "A registrar that reports a rejected registration prevents the mediator from being created.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto registrar = std::make_shared<StubRegistrar>([](common::MediatorRegistries&) {
        return false;
    });

    const auto mediator = Create({registrar});

    ASSERT_FALSE(mediator.has_value());
    EXPECT_EQ(mediator.error(), DaemonErrorCode::kInternalError);
}

TEST_F(MediatorFactoryTest, DuplicateRegistrationFailsCreation)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__registration");
    RecordProperty("Description", "Registering the same key twice prevents the mediator from being created.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto query = std::make_shared<StubMediatorQuery>(1U);
    const auto registrar = std::make_shared<StubRegistrar>([&query](common::MediatorRegistries& registries) {
        return registries.mediator_queries.Register(kQueryAction, query) &&
               registries.mediator_queries.Register(kQueryAction, query);
    });

    const auto mediator = Create({registrar});

    EXPECT_FALSE(mediator.has_value());
}

TEST_F(MediatorFactoryTest, NullRegistrarFailsCreation)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__registration");
    RecordProperty("Description", "A null registrar prevents the mediator from being created.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto mediator = Create({nullptr});

    ASSERT_FALSE(mediator.has_value());
    EXPECT_EQ(mediator.error(), DaemonErrorCode::kInternalError);
}

TEST_F(MediatorFactoryTest, QueryRegisteredForABuiltInOperationFailsCreation)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__registration");
    RecordProperty("Description",
                   "A query registered for an operation the mediator implements itself prevents its creation.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto query = std::make_shared<StubMediatorQuery>(1U);
    const auto registrar = std::make_shared<StubRegistrar>([&query](common::MediatorRegistries& registries) {
        return registries.mediator_queries.Register(operations::CTX_CLOSE, query);
    });

    const auto mediator = Create({registrar});

    ASSERT_FALSE(mediator.has_value());
    EXPECT_EQ(mediator.error(), DaemonErrorCode::kInvalidArgument);
}

}  // namespace
}  // namespace score::crypto::daemon::mediator

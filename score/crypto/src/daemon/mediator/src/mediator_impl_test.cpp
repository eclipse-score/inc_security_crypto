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

#include "score/crypto/src/daemon/mediator/mediator_impl.hpp"

#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/config/inc/config.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"
#include "score/crypto/src/daemon/mediator/src/context_assembler.hpp"
#include "score/crypto/src/daemon/mediator/src/handler_selector.hpp"
#include "score/crypto/src/daemon/mediator/src/mediator_test_doubles.hpp"
#include "score/crypto/src/daemon/mediator/src/provider_arbiter.hpp"
#include "score/crypto/src/daemon/provider/provider_manager.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace score::crypto::daemon::mediator
{
namespace
{

using common::CryptoProviderType;
using common::DaemonErrorCode;
using common::ProviderCapability;
using test_doubles::RecordingDataManager;
using test_doubles::StubProvider;
using CryptoError = score::crypto::CryptoErrorCode;
using ActionCode = std::decay_t<decltype(operations::CUSTOM_OP_START)>;

constexpr std::uint64_t kClient = 7U;
constexpr std::uint8_t kHardwarePreferredWire = 3U;
// Operation codes outside the built-in set, used for mediator query registration.
constexpr ActionCode kQueryAction = static_cast<ActionCode>(operations::CUSTOM_OP_START + 1U);
constexpr ActionCode kUnlistedAction = static_cast<ActionCode>(operations::CUSTOM_OP_START + 2U);

// Exercises CTX_CREATE through the real mediator, ProviderManager, ProviderArbiter,
// ContextAssembler, and DataManager. StubProvider instances supply controlled provider-side
// behavior; their factories create StubHandlers that record initialization and can inject
// failures. RecordingDataManager forwards to a real DataManager and records context children
// so tests can verify creation and rollback.
class MediatorContextCreationTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        m_data_manager = std::make_shared<RecordingDataManager>();
        m_provider_manager = std::make_shared<provider::ProviderManager>(config::ProviderInitConfig{});
        m_software = Register("SW", CryptoProviderType::SOFTWARE);
        m_hardware = Register("HW", CryptoProviderType::HARDWARE);
        m_provider_manager->Initialize();

        const auto connection =
            m_data_manager->addNode(kClient, std::make_shared<data_manager::DataNode>(/*exclusiveAccess=*/false));
        ASSERT_TRUE(connection.has_value());
        // This connection is added directly; only later addChildNode calls are recorded as contexts.
        m_connection_id = connection.value();

        // Tests register entries after construction. The mediator reads the registries through shared
        // pointers at request time, so later registrations are visible to it.
        m_context_factories = std::make_shared<ContextFactoryRegistry>();
        m_resource_resolvers = std::make_shared<ResourceResolverRegistry>();
        m_mediator_queries = std::make_shared<MediatorQueryRegistry>();

        MediatorDependencies deps;
        deps.data_manager = m_data_manager;
        deps.provider_manager = m_provider_manager;
        auto arbiter = std::make_shared<ProviderArbiter>(m_provider_manager, nullptr);
        auto handler_selector = std::make_shared<HandlerSelector>(arbiter, m_context_factories);
        deps.handler_selector = handler_selector;
        deps.assembler = std::make_shared<ContextAssembler>(m_data_manager, nullptr);
        deps.resource_resolvers = m_resource_resolvers;
        deps.mediator_queries = m_mediator_queries;
        m_mediator = std::make_unique<MediatorImpl>(std::move(deps));
    }

    std::shared_ptr<StubProvider> Register(const std::string& name, const CryptoProviderType type)
    {
        auto stub = std::make_shared<StubProvider>(name, ProviderCapability::kCrypto);
        EXPECT_TRUE(m_provider_manager->RegisterProvider(name, stub, type));
        return stub;
    }

    static control_plane::protocol::SingleOperationRequest Operation(
        const control_plane::protocol::OperationIdentifier& id,
        common::RequestParameters parameters = {})
    {
        control_plane::protocol::SingleOperationRequest operation{};
        operation.operationId = id;
        operation.parameters = std::move(parameters);
        return operation;
    }

    // Sends the operations as one request addressed to @p node_id and returns the responses.
    std::vector<control_plane::protocol::SingleOperationResponse> Process(
        const data_manager::DataNodeId node_id,
        std::vector<control_plane::protocol::SingleOperationRequest> operations)
    {
        control_plane::ControlRequest request{};
        request.request_id = 1U;
        request.client_id = kClient;
        request.data_node_id = node_id;
        request.operation.operations = std::move(operations);
        return m_mediator->processRequest(request).operation.operations;
    }

    control_plane::protocol::SingleOperationResponse CreateContext(common::RequestParameters parameters)
    {
        const auto responses =
            Process(m_connection_id, {Operation(operations::CreateContext(), std::move(parameters))});
        EXPECT_EQ(responses.size(), 1U);
        return responses.at(0U);
    }

    // Creates a HASH context and returns its node id and the handler behind it.
    std::pair<data_manager::DataNodeId, std::shared_ptr<test_doubles::StubHandler>> CreateHashContext()
    {
        const auto response = CreateContext(HashRequest());
        EXPECT_EQ(response.result, control_plane::protocol::OPERATION_RESULT_SUCCESS);
        const auto context_id = response.getParameter<std::uint64_t>(0U);
        EXPECT_TRUE(context_id.has_value());
        // Either provider may be selected; each stub factory retains the handler it created.
        const auto handler = (m_software->Factory()->LastHandler() != nullptr) ? m_software->Factory()->LastHandler()
                                                                               : m_hardware->Factory()->LastHandler();
        return {context_id.value_or(0U), handler};
    }

    static control_plane::protocol::OperationIdentifier HandlerOperation()
    {
        return control_plane::protocol::OperationIdentifier{.operationActor = common::actors::OP_ACTOR_HASH_HANDLER,
                                                            .operationAction = 1U};
    }

    static common::RequestParameters HashRequest(const std::string_view algorithm = "SHA256")
    {
        return common::RequestParameters{std::string_view{"HASH"}, algorithm};
    }

    static control_plane::protocol::OperationResult ResultOf(const CryptoError error)
    {
        return static_cast<control_plane::protocol::OperationResult>(error);
    }

    static control_plane::protocol::OperationIdentifier MediatorOperation(const ActionCode action)
    {
        return control_plane::protocol::OperationIdentifier{.operationActor = common::actors::OP_ACTOR_MEDIATOR,
                                                            .operationAction = action};
    }

    std::shared_ptr<RecordingDataManager> m_data_manager;
    provider::ProviderManager::Sptr m_provider_manager;
    std::shared_ptr<StubProvider> m_software;
    std::shared_ptr<StubProvider> m_hardware;
    std::shared_ptr<ContextFactoryRegistry> m_context_factories;
    std::shared_ptr<ResourceResolverRegistry> m_resource_resolvers;
    std::shared_ptr<MediatorQueryRegistry> m_mediator_queries;
    data_manager::DataNodeId m_connection_id{0U};
    std::unique_ptr<MediatorImpl> m_mediator;
};

TEST_F(MediatorContextCreationTest, ValidRequestCreatesAContextAndReturnsItsId)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__assembly");
    RecordProperty("Description", "A valid CTX_CREATE returns the id of a new, initialized context node.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto response = CreateContext(HashRequest());

    ASSERT_EQ(response.result, control_plane::protocol::OPERATION_RESULT_SUCCESS);
    const auto context_id = response.getParameter<std::uint64_t>(0U);
    ASSERT_TRUE(context_id.has_value());
    EXPECT_TRUE(m_data_manager->NodeExists(kClient, context_id.value()));
    const auto created = (m_software->Factory()->LastHandler() != nullptr) ? m_software->Factory()->LastHandler()
                                                                           : m_hardware->Factory()->LastHandler();
    ASSERT_NE(created, nullptr);
    EXPECT_EQ(created->InitCalls(), 1);
    EXPECT_EQ(created->LastParams().context_node_id, context_id.value());
}

TEST_F(MediatorContextCreationTest, InvalidRequestIsRefusedWithoutSelectingAProviderOrCreatingANode)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__decode_validate");
    RecordProperty("Description",
                   "A request that fails validation is refused before any provider is asked and before any "
                   "node is created.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto response = CreateContext(HashRequest("NOT_AN_ALGORITHM"));

    EXPECT_EQ(response.result, ResultOf(CryptoError::kUnsupportedAlgorithm));
    EXPECT_EQ(m_software->Factory()->CreateCalls(), 0);
    EXPECT_EQ(m_hardware->Factory()->CreateCalls(), 0);
    EXPECT_TRUE(m_data_manager->AddedChildren().empty());
}

TEST_F(MediatorContextCreationTest, ValidationFailureReportsTheFirstFailingCheck)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__decode_validate");
    RecordProperty("Description",
                   "A request with a missing key for a keyed context and an unknown algorithm reports the key "
                   "failure, which is checked first.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto response =
        CreateContext(common::RequestParameters{std::string_view{"SIGN"}, std::string_view{"NOT_AN_ALGORITHM"}});

    EXPECT_EQ(response.result, ResultOf(CryptoError::kInvalidArgument));
    EXPECT_TRUE(m_data_manager->AddedChildren().empty());
}

TEST_F(MediatorContextCreationTest, CreationParametersReachTheHandlerUnchanged)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__handler_semantics");
    RecordProperty("Description",
                   "Parameters beyond the common prefix are not interpreted by the mediator and reach the "
                   "handler unchanged.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    auto parameters = HashRequest();
    parameters.push_back(std::uint8_t{0U});    // [2] provider preference
    parameters.push_back(common::NoParam{});   // [3] no key
    parameters.push_back(std::uint8_t{201U});  // [4] a value no mediator rule knows
    const auto response = CreateContext(parameters);

    ASSERT_EQ(response.result, control_plane::protocol::OPERATION_RESULT_SUCCESS);
    const auto handler = (m_software->Factory()->LastHandler() != nullptr) ? m_software->Factory()->LastHandler()
                                                                           : m_hardware->Factory()->LastHandler();
    ASSERT_NE(handler, nullptr);
    const auto& delivered = handler->LastParams().context_creation_params;
    ASSERT_EQ(delivered.size(), parameters.size());
    EXPECT_EQ(std::get<std::uint8_t>(delivered[4]), 201U);
}

TEST_F(MediatorContextCreationTest, HandlerInitializationErrorIsReturnedAndTheNodeIsRemoved)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__handler_semantics");
    RecordProperty("Description",
                   "When the handler rejects its initialization the client receives the handler's error and "
                   "no node remains.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    // Default provider selection can choose either provider, so both factories inject the same init failure.
    m_software->Factory()->FailHandlerInitializationWith(DaemonErrorCode::kInvalidArgument);
    m_hardware->Factory()->FailHandlerInitializationWith(DaemonErrorCode::kInvalidArgument);

    const auto response = CreateContext(HashRequest());

    EXPECT_EQ(response.result, ResultOf(CryptoError::kInvalidArgument));
    ASSERT_EQ(m_data_manager->AddedChildren().size(), 1U);
    EXPECT_FALSE(m_data_manager->NodeExists(kClient, m_data_manager->AddedChildren().front()));
}

TEST_F(MediatorContextCreationTest, DaemonErrorsAreReportedAsTheirPublicCounterparts)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__error_mapping");
    RecordProperty("Description", "A daemon error code reaches the client as its public counterpart.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    for (const auto& [daemon_error, public_error] :
         {std::pair{DaemonErrorCode::kResourceNotFound, CryptoError::kResourceNotFound},
          std::pair{DaemonErrorCode::kOperationFailed, CryptoError::kOperationFailed},
          std::pair{DaemonErrorCode::kUnsupportedOperation, CryptoError::kUnsupportedOperation}})
    {
        // The stub handler returns this daemon error during initialization; the mediator maps it for the client.
        m_software->Factory()->FailHandlerInitializationWith(daemon_error);
        m_hardware->Factory()->FailHandlerInitializationWith(daemon_error);

        const auto response = CreateContext(HashRequest());

        EXPECT_EQ(response.result, ResultOf(public_error));
    }
}

TEST_F(MediatorContextCreationTest, FallbackProviderServesTheRequestWhenThePrimaryCannotCreateTheHandler)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__fallback");
    RecordProperty("Description",
                   "A hardware-preferred request with a software fallback is served by the software provider "
                   "when the hardware provider cannot create the handler.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    m_hardware->Factory()->FailWith(CryptoError::kUnsupportedAlgorithm);
    auto parameters = HashRequest();
    parameters.push_back(kHardwarePreferredWire);

    const auto response = CreateContext(parameters);

    ASSERT_EQ(response.result, control_plane::protocol::OPERATION_RESULT_SUCCESS);
    EXPECT_EQ(m_hardware->Factory()->CreateCalls(), 1);
    EXPECT_EQ(m_software->Factory()->CreateCalls(), 1);
}

TEST_F(MediatorContextCreationTest, KeyReferenceWithoutKeyManagementIsRefusedAndLeavesNoNode)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__key_authorization");
    RecordProperty("Description",
                   "A context that references a key cannot be created when key management is absent, and no "
                   "node remains.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto response = CreateContext(common::RequestParameters{
        std::string_view{"SIGN"}, std::string_view{"ECDSA-P256-SHA256"}, common::NoParam{}, std::uint64_t{5U}});

    EXPECT_NE(response.result, control_plane::protocol::OPERATION_RESULT_SUCCESS);
    ASSERT_EQ(m_data_manager->AddedChildren().size(), 1U);
    EXPECT_FALSE(m_data_manager->NodeExists(kClient, m_data_manager->AddedChildren().front()));
}

TEST_F(MediatorContextCreationTest, OperationOnAContextIsDeliveredToItsHandler)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__forwarding");
    RecordProperty("Description",
                   "An operation addressed to a context runs on that context's handler with the request "
                   "parameters, and the handler's response parameters are returned.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto [context_id, handler] = CreateHashContext();
    // The stub returns this payload so the test can verify mediator response forwarding.
    handler->SetExecuteResponse(common::ResponseParameters{std::uint64_t{99U}});

    const auto responses = Process(context_id, {Operation(HandlerOperation(), {std::uint8_t{5U}})});

    ASSERT_EQ(responses.size(), 1U);
    EXPECT_EQ(responses[0].result, control_plane::protocol::OPERATION_RESULT_SUCCESS);
    EXPECT_EQ(responses[0].getParameter<std::uint64_t>(0U).value_or(0U), 99U);
    ASSERT_EQ(handler->ExecuteCalls(), 1);
    EXPECT_EQ(handler->LastOperationId().operationActor, common::actors::OP_ACTOR_HASH_HANDLER);
    ASSERT_EQ(handler->LastExecuteParameters().size(), 1U);
    EXPECT_EQ(std::get<std::uint8_t>(handler->LastExecuteParameters()[0]), 5U);
}

TEST_F(MediatorContextCreationTest, HandlerErrorOnAnOperationIsReturnedToTheClient)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__forwarding");
    RecordProperty("Description", "A failed operation on a context returns the handler's error as a public code.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto [context_id, handler] = CreateHashContext();
    handler->FailExecuteWith(DaemonErrorCode::kOperationFailed);

    const auto responses = Process(context_id, {Operation(HandlerOperation())});

    ASSERT_EQ(responses.size(), 1U);
    EXPECT_EQ(responses[0].result, ResultOf(CryptoError::kOperationFailed));
}

TEST_F(MediatorContextCreationTest, OperationAddressedToANodeThatIsNotAContextIsRefused)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__forwarding");
    RecordProperty("Description",
                   "An operation addressed to the connection node, or to a node that does not exist, is "
                   "refused as an invalid argument.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto [context_id, handler] = CreateHashContext();

    const auto to_connection = Process(m_connection_id, {Operation(HandlerOperation())});
    const auto to_missing = Process(context_id + 1000U, {Operation(HandlerOperation())});

    ASSERT_EQ(to_connection.size(), 1U);
    EXPECT_EQ(to_connection[0].result, ResultOf(CryptoError::kInvalidArgument));
    ASSERT_EQ(to_missing.size(), 1U);
    EXPECT_EQ(to_missing[0].result, ResultOf(CryptoError::kInvalidArgument));
    EXPECT_EQ(handler->ExecuteCalls(), 0);
}

TEST_F(MediatorContextCreationTest, ClosingAContextRemovesItsNode)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__close");
    RecordProperty("Description", "Closing a context removes its node, and closing it again also succeeds.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto [context_id, handler] = CreateHashContext();
    ASSERT_TRUE(m_data_manager->NodeExists(kClient, context_id));

    const auto first = Process(context_id, {Operation(operations::CloseContext())});
    EXPECT_FALSE(m_data_manager->NodeExists(kClient, context_id));
    const auto second = Process(context_id, {Operation(operations::CloseContext())});

    ASSERT_EQ(first.size(), 1U);
    EXPECT_EQ(first[0].result, control_plane::protocol::OPERATION_RESULT_SUCCESS);
    ASSERT_EQ(second.size(), 1U);
    EXPECT_EQ(second[0].result, control_plane::protocol::OPERATION_RESULT_SUCCESS);
}

TEST_F(MediatorContextCreationTest, RequestStopsAtTheFirstFailingOperation)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__stop_on_failure");
    RecordProperty("Description",
                   "Operations after a failing operation in the same request are not run, and the response "
                   "carries only the operations processed.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto responses = Process(m_connection_id,
                                   {Operation(operations::CreateContext(), HashRequest("NOT_AN_ALGORITHM")),
                                    Operation(operations::CreateContext(), HashRequest())});

    ASSERT_EQ(responses.size(), 1U);
    EXPECT_EQ(responses[0].result, ResultOf(CryptoError::kUnsupportedAlgorithm));
    EXPECT_EQ(m_software->Factory()->CreateCalls(), 0);
    EXPECT_EQ(m_hardware->Factory()->CreateCalls(), 0);
    EXPECT_TRUE(m_data_manager->AddedChildren().empty());
}

// ============================================================================
// Context factories, mediator queries and resource resolvers registered with the mediator
// ============================================================================

TEST_F(MediatorContextCreationTest, RegisteredFactoryCreatesTheContextWithoutProviderSelection)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__context_factory");
    RecordProperty("Description",
                   "A context type with a registered factory is created by that factory, and no provider "
                   "factory is called.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    auto factory = std::make_shared<test_doubles::StubContextFactory>();
    ASSERT_TRUE(m_context_factories->Register("HASH", factory));

    const auto response = CreateContext(HashRequest());

    ASSERT_EQ(response.result, control_plane::protocol::OPERATION_RESULT_SUCCESS);
    const auto context_id = response.getParameter<std::uint64_t>(0U);
    ASSERT_TRUE(context_id.has_value());
    EXPECT_TRUE(m_data_manager->NodeExists(kClient, context_id.value()));
    EXPECT_EQ(factory->CreateCalls(), 1);
    ASSERT_NE(factory->LastHandler(), nullptr);
    EXPECT_EQ(factory->LastHandler()->InitCalls(), 1);
    EXPECT_EQ(m_software->Factory()->CreateCalls(), 0);
    EXPECT_EQ(m_hardware->Factory()->CreateCalls(), 0);
}

TEST_F(MediatorContextCreationTest, RegisteredFactoryErrorIsReturnedAndNoNodeIsCreated)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__context_factory");
    RecordProperty("Description",
                   "When a registered factory fails, the client receives its error and no context node is "
                   "created.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    auto factory = std::make_shared<test_doubles::StubContextFactory>();
    factory->FailWith(DaemonErrorCode::kOperationFailed);
    ASSERT_TRUE(m_context_factories->Register("HASH", factory));

    const auto response = CreateContext(HashRequest());

    EXPECT_EQ(response.result, ResultOf(CryptoError::kOperationFailed));
    EXPECT_EQ(factory->CreateCalls(), 1);
    EXPECT_TRUE(m_data_manager->AddedChildren().empty());
}

TEST_F(MediatorContextCreationTest, KeyedRequestForRegisteredFactoryIsRefusedBeforeTheFactoryRuns)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__context_factory");
    RecordProperty(
        "Description",
        "A context type served by a factory that references a key is refused as not permitted, and its factory "
        "is not called.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    auto factory = std::make_shared<test_doubles::StubContextFactory>();
    ASSERT_TRUE(m_context_factories->Register("SIGN", factory));

    const auto response = CreateContext(common::RequestParameters{
        std::string_view{"SIGN"}, std::string_view{"ECDSA-P256-SHA256"}, common::NoParam{}, std::uint64_t{5U}});

    EXPECT_EQ(response.result, ResultOf(CryptoError::kKeyOperationNotPermitted));
    EXPECT_EQ(factory->CreateCalls(), 0);
    EXPECT_TRUE(m_data_manager->AddedChildren().empty());
}

TEST_F(MediatorContextCreationTest, QueryAtABuiltInCodeIsNeverCalledWhenTheMediatorIsBuiltDirectly)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__query_dispatch");
    RecordProperty("Description",
                   "A mediator built without the factory, whose query registry holds a query at a built-in "
                   "operation code, still runs the built-in handler and never calls the query. The factory "
                   "rejects the same registration at startup.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    auto query = std::make_shared<test_doubles::StubMediatorQuery>(std::uint64_t{77U});
    ASSERT_TRUE(m_mediator_queries->Register(operations::CTX_CREATE, query));

    const auto response = CreateContext(HashRequest());

    EXPECT_EQ(response.result, control_plane::protocol::OPERATION_RESULT_SUCCESS);
    EXPECT_EQ(query->Calls(), 0);
    EXPECT_EQ(m_software->Factory()->CreateCalls() + m_hardware->Factory()->CreateCalls(), 1);
}

TEST_F(MediatorContextCreationTest, MediatorQueryHandlesItsOperationCode)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__query_dispatch");
    RecordProperty("Description",
                   "An operation code without a built-in handler is dispatched to the query registered for it, "
                   "and the query's result is returned.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    auto query = std::make_shared<test_doubles::StubMediatorQuery>(std::uint64_t{77U});
    ASSERT_TRUE(m_mediator_queries->Register(kQueryAction, query));

    const auto responses = Process(m_connection_id, {Operation(MediatorOperation(kQueryAction))});

    ASSERT_EQ(responses.size(), 1U);
    EXPECT_EQ(responses[0].result, control_plane::protocol::OPERATION_RESULT_SUCCESS);
    EXPECT_EQ(responses[0].getParameter<std::uint64_t>(0U).value_or(0U), 77U);
    EXPECT_EQ(query->Calls(), 1);
    EXPECT_EQ(query->LastClientId(), kClient);
}

TEST_F(MediatorContextCreationTest, UnregisteredOperationCodeIsNotDispatchedToAnyQuery)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__query_dispatch");
    RecordProperty("Description",
                   "An operation code with no built-in handler and no registered query is not dispatched, and the "
                   "request does not succeed.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    auto query = std::make_shared<test_doubles::StubMediatorQuery>(std::uint64_t{77U});
    ASSERT_TRUE(m_mediator_queries->Register(kQueryAction, query));

    const auto responses = Process(m_connection_id, {Operation(MediatorOperation(kUnlistedAction))});

    EXPECT_EQ(query->Calls(), 0);
    EXPECT_TRUE(responses.empty() || responses[0].result != control_plane::protocol::OPERATION_RESULT_SUCCESS);
}

TEST_F(MediatorContextCreationTest, ResourceResolverReceivesTheClientAndNameAndReturnsItsResult)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__res_resolution");
    RecordProperty("Description",
                   "A resource request is resolved by the resolver registered for its resource type, which receives "
                   "the client, session and name, and whose result is returned.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    auto resolver = std::make_shared<test_doubles::StubResourceResolver>(true, std::uint64_t{42U});
    ASSERT_TRUE(m_resource_resolvers->Register(score::crypto::ResourceType::kKeySlot, resolver));

    const auto responses =
        Process(m_connection_id,
                {Operation(operations::ResolveResource(),
                           {std::string_view{"my_key"},
                            std::uint64_t{static_cast<std::uint64_t>(score::crypto::ResourceType::kKeySlot)}})});

    ASSERT_EQ(responses.size(), 1U);
    EXPECT_EQ(responses[0].result, control_plane::protocol::OPERATION_RESULT_SUCCESS);
    EXPECT_EQ(responses[0].getParameter<std::uint64_t>(0U).value_or(0U), 42U);
    EXPECT_EQ(resolver->Calls(), 1);
    EXPECT_EQ(resolver->LastClientId(), kClient);
    EXPECT_EQ(resolver->LastSessionId(), m_connection_id);
    EXPECT_EQ(resolver->LastResourceName(), "my_key");
}

TEST_F(MediatorContextCreationTest, ResourceTypeWithoutRegisteredResolverIsUnsupported)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__res_resolution");
    RecordProperty("Description",
                   "A resource request for a resource type with no registered resolver is refused as unsupported.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto responses =
        Process(m_connection_id,
                {Operation(operations::ResolveResource(),
                           {std::string_view{"my_key"},
                            std::uint64_t{static_cast<std::uint64_t>(score::crypto::ResourceType::kKeySlot)}})});

    ASSERT_EQ(responses.size(), 1U);
    EXPECT_EQ(responses[0].result, ResultOf(CryptoError::kUnsupportedOperation));
}

}  // namespace
}  // namespace score::crypto::daemon::mediator

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

#include "score/crypto/src/daemon/mediator/src/context_assembler.hpp"

#include "score/crypto/src/daemon/common/context/context_data_node.hpp"
#include "score/crypto/src/daemon/key_management/core/key_management_service.hpp"
#include "score/crypto/src/daemon/key_management/slot/slot_registry.hpp"
#include "score/crypto/src/daemon/mediator/src/mediator_test_doubles.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <string_view>

namespace score::crypto::daemon::mediator
{
namespace
{

using common::DaemonErrorCode;
using test_doubles::RecordingDataManager;
using test_doubles::StubHandler;

constexpr std::uint64_t kClient = 7U;
constexpr common::ProviderId kProvider = 3U;

// Exercises the real ContextAssembler and DataManager lifecycle. RecordingDataManager forwards to
// a real DataManager while tracking context children and deletions; StubHandler records its init
// parameters and can inject initialization failures. When requested, key management is also real
// but uses an empty slot registry, so tests can distinguish missing service from missing key.
class ContextAssemblerTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        m_data_manager = std::make_shared<RecordingDataManager>();
        const auto connection =
            m_data_manager->addNode(kClient, std::make_shared<data_manager::DataNode>(/*exclusiveAccess=*/false));
        ASSERT_TRUE(connection.has_value());
        // The wrapper records addChildNode calls, not this directly added connection node.
        m_connection_id = connection.value();
    }

    ContextAssembler MakeAssembler(const bool with_key_management = false)
    {
        key_management::KeyManagementService::Sptr km_service;
        if (with_key_management)
        {
            // This is a real service with no registered key nodes, for testing resolution failures.
            km_service = std::make_shared<key_management::KeyManagementService>(
                m_data_manager, nullptr, std::make_shared<key_management::SlotRegistry>());
        }
        return ContextAssembler{m_data_manager, km_service};
    }

    ContextAssemblyRequest Request(const std::string_view context_type,
                                   const std::optional<std::uint64_t> key_node_id = std::nullopt)
    {
        return ContextAssemblyRequest{.client_id = kClient,
                                      .connection_id = m_connection_id,
                                      .provider_id = kProvider,
                                      .algorithm = ::score::crypto::GetAlgorithmDescriptor("SHA256"),
                                      .context_type = context_type,
                                      .key_node_id = key_node_id,
                                      .mode = std::nullopt,
                                      .raw_parameters = m_raw_parameters};
    }

    common::RequestParameters m_raw_parameters{std::string_view{"HASH"}, std::string_view{"SHA256"}};
    std::shared_ptr<RecordingDataManager> m_data_manager;
    data_manager::DataNodeId m_connection_id{0U};
};

TEST_F(ContextAssemblerTest, CreatesContextNodeAndInitializesTheHandler)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__assembly");
    RecordProperty("Description",
                   "Assembly adds the context node under the connection and initializes the handler with the "
                   "client, node and provider.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto handler = std::make_shared<StubHandler>();
    const auto assembler = MakeAssembler();

    const auto node_id = assembler.Assemble(Request("HASH"), handler);

    ASSERT_TRUE(node_id.has_value());
    EXPECT_TRUE(m_data_manager->NodeExists(kClient, node_id.value()));
    auto accessor = m_data_manager->getNodeAccessor(kClient, node_id.value());
    ASSERT_TRUE(accessor.has_value());
    auto context_node = std::move(accessor).value().downCast<provider::handler::ContextDataNode>();
    ASSERT_TRUE(context_node.has_value());
    EXPECT_EQ(context_node.value()->GetHandler(), handler);
    ASSERT_TRUE(context_node.value()->GetAlgorithm().has_value());
    EXPECT_EQ(context_node.value()->GetAlgorithm()->id, ::score::crypto::GetAlgorithmDescriptor("SHA256")->id);
    ASSERT_EQ(handler->InitCalls(), 1);
    EXPECT_EQ(handler->LastParams().client_id, kClient);
    EXPECT_EQ(handler->LastParams().context_node_id, node_id.value());
    EXPECT_EQ(handler->LastParams().provider_id, kProvider);
    EXPECT_EQ(handler->LastParams().bound_key_handler, nullptr);
    EXPECT_TRUE(m_data_manager->Deleted().empty());
}

TEST_F(ContextAssemblerTest, DeliversTheCreationParametersToTheHandlerUnchanged)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__handler_semantics");
    RecordProperty("Description", "The creation parameters reach the handler's initialization unchanged.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    m_raw_parameters.push_back(std::uint8_t{0U});
    m_raw_parameters.push_back(std::uint8_t{1U});
    m_raw_parameters.push_back(std::uint8_t{9U});
    const auto handler = std::make_shared<StubHandler>();
    const auto assembler = MakeAssembler();

    ASSERT_TRUE(assembler.Assemble(Request("HASH"), handler).has_value());

    const auto& delivered = handler->LastParams().context_creation_params;
    ASSERT_EQ(delivered.size(), m_raw_parameters.size());
    EXPECT_EQ(std::get<std::string_view>(delivered[0]), "HASH");
    EXPECT_EQ(std::get<std::string_view>(delivered[1]), "SHA256");
    EXPECT_EQ(std::get<std::uint8_t>(delivered[4]), 9U);
}

TEST_F(ContextAssemblerTest, HandlerInitializationFailureRemovesTheContextNode)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__assembly");
    RecordProperty("Description", "A failed handler initialization removes the node the assembly created.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    // StubHandler returns this error from InitializeContext after the context child is created.
    const auto handler = std::make_shared<StubHandler>(DaemonErrorCode::kInvalidArgument);
    const auto assembler = MakeAssembler();

    const auto node_id = assembler.Assemble(Request("HASH"), handler);

    ASSERT_FALSE(node_id.has_value());
    EXPECT_EQ(node_id.error(), DaemonErrorCode::kInvalidArgument);
    ASSERT_EQ(m_data_manager->AddedChildren().size(), 1U);
    const auto created = m_data_manager->AddedChildren().front();
    EXPECT_EQ(m_data_manager->Deleted(), std::vector<data_manager::DataNodeId>{created});
    EXPECT_FALSE(m_data_manager->NodeExists(kClient, created));
}

TEST_F(ContextAssemblerTest, UnknownConnectionFailsWithoutLeavingANode)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__assembly");
    RecordProperty("Description", "A context cannot be added under a connection that does not exist.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto handler = std::make_shared<StubHandler>();
    const auto assembler = MakeAssembler();
    auto request = Request("HASH");
    request.connection_id = m_connection_id + 1000U;

    const auto node_id = assembler.Assemble(request, handler);

    ASSERT_FALSE(node_id.has_value());
    EXPECT_TRUE(m_data_manager->AddedChildren().empty());
    EXPECT_EQ(handler->InitCalls(), 0);
}

TEST_F(ContextAssemblerTest, KeyReferenceWithoutKeyManagementRemovesTheContextNode)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__assembly");
    RecordProperty("Description", "A key reference cannot be bound without key management; the node is removed.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto handler = std::make_shared<StubHandler>();
    const auto assembler = MakeAssembler(/*with_key_management=*/false);

    const auto node_id = assembler.Assemble(Request("SIGN", 5U), handler);

    ASSERT_FALSE(node_id.has_value());
    EXPECT_EQ(node_id.error(), DaemonErrorCode::kUnsupportedOperation);
    // Key binding fails before initialization; the child created earlier in assembly is rolled back.
    EXPECT_EQ(handler->InitCalls(), 0);
    ASSERT_EQ(m_data_manager->AddedChildren().size(), 1U);
    EXPECT_FALSE(m_data_manager->NodeExists(kClient, m_data_manager->AddedChildren().front()));
}

TEST_F(ContextAssemblerTest, UnknownKeyFailsBindingAndRemovesTheContextNode)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__assembly");
    RecordProperty("Description", "A key that cannot be resolved fails the binding and the node is removed.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto handler = std::make_shared<StubHandler>();
    const auto assembler = MakeAssembler(/*with_key_management=*/true);

    const auto node_id = assembler.Assemble(Request("SIGN", 5U), handler);

    ASSERT_FALSE(node_id.has_value());
    // The real service has no node 5, so binding fails before the stub handler is initialized.
    EXPECT_EQ(handler->InitCalls(), 0);
    ASSERT_EQ(m_data_manager->AddedChildren().size(), 1U);
    EXPECT_FALSE(m_data_manager->NodeExists(kClient, m_data_manager->AddedChildren().front()));
}

TEST_F(ContextAssemblerTest, ContextTypeThatTakesNoKeyIsRefusedBeforeTheKeyIsLookedUp)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__key_authorization");
    RecordProperty("Description",
                   "A key reference on a context type that consumes no key permission is refused as not "
                   "permitted, decided from the context type alone.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto handler = std::make_shared<StubHandler>();
    const auto assembler = MakeAssembler(/*with_key_management=*/true);

    const auto node_id = assembler.Assemble(Request("HASH", 5U), handler);

    ASSERT_FALSE(node_id.has_value());
    EXPECT_EQ(node_id.error(), DaemonErrorCode::kKeyOperationNotPermitted);
    // HASH does not consume key permission, so the request is rejected before resolving the absent key.
    EXPECT_EQ(handler->InitCalls(), 0);
}

}  // namespace
}  // namespace score::crypto::daemon::mediator

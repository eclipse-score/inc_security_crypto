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

#ifndef SCORE_CRYPTO_SRC_DAEMON_MEDIATOR_MEDIATOR_TEST_DOUBLES_HPP
#define SCORE_CRYPTO_SRC_DAEMON_MEDIATOR_MEDIATOR_TEST_DOUBLES_HPP

/// @file mediator_test_doubles.hpp
/// @brief Test doubles for exercising the mediator with real collaborators wherever possible.
///
/// The mediator tests use the real `ProviderManager`, `DataManager`, `ProviderArbiter` and
/// `ContextAssembler`. Only the parts that stand for external subsystems are replaced:
///
/// - `StubProvider` is a provider with configurable capabilities. It is registered with a real
///   `ProviderManager`, which assigns its id when the manager initializes it.
/// - `StubHandlerFactory` is the provider's handler factory. It creates `StubHandler`s, or fails
///   with a configured error.
/// - `StubHandler` is the context handler. It records how it was initialized and operated on, and
///   fails on request.
/// - `RecordingDataManager` wraps a real `DataManager` and records which context nodes were added
///   and deleted, so that tests can check rollback.
///
/// Typical wiring:
/// @code
///   auto manager = std::make_shared<provider::ProviderManager>(config::ProviderInitConfig{});
///   auto software = std::make_shared<StubProvider>("SW", common::ProviderCapability::kCrypto);
///   manager->RegisterProvider("SW", software, common::CryptoProviderType::SOFTWARE);
///   manager->Initialize();  // assigns provider ids; register all providers first
///
///   software->Factory()->FailWith(CryptoErrorCode::kUnsupportedAlgorithm);  // configure behaviour
///   // ... run the unit under test ...
///   EXPECT_EQ(software->Factory()->CreateCalls(), 1);                      // inspect what happened
/// @endcode

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/algorithm_catalog.hpp"
#include "score/crypto/src/daemon/common/context/handler_init_params.hpp"
#include "score/crypto/src/daemon/common/context/i_handler.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/data_manager/data_manager.hpp"
#include "score/crypto/src/daemon/data_manager/data_node_accessor.hpp"
#include "score/crypto/src/daemon/data_manager/i_data_manager.hpp"
#include "score/crypto/src/daemon/provider/handler/i_crypto_handler_factory.hpp"
#include "score/crypto/src/daemon/provider/i_provider.hpp"
#include "score/result/result.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace score::crypto::daemon::mediator::test_doubles
{

/// @brief Context handler that records how it is used and fails on request.
///
/// It records the initialization parameters and each executed operation. Initialization fails with
/// the error given at construction. Execution returns a configured response, or fails with a
/// configured error. `Reset` always succeeds.
class StubHandler final : public provider::handler::Handler
{
  public:
    /// @brief Create a handler.
    /// @param init_error Error that `InitializeContext` returns, or none for success.
    explicit StubHandler(std::optional<common::DaemonErrorCode> init_error = std::nullopt) : m_init_error{init_error} {}

    /// @brief Record the initialization parameters and return the configured result.
    /// @param init_params Parameters supplied by the unit under test; kept for `LastParams`.
    /// @return Success, or the error given at construction.
    Expected<std::monostate, common::DaemonErrorCode> InitializeContext(
        const provider::handler::InitializationParams& init_params) override
    {
        ++m_init_calls;
        m_last_params = init_params;
        if (m_init_error.has_value())
        {
            return make_unexpected(m_init_error.value());
        }
        return std::monostate{};
    }

    /// @brief Record the operation and its parameters and return the configured result.
    /// @param operation_id Operation requested; kept for `LastOperationId`.
    /// @param request Parameters of the operation; a copy is kept for `LastExecuteParameters`.
    /// @return The response set by `SetExecuteResponse` (empty by default), or the error set by
    ///         `FailExecuteWith`.
    Expected<common::ResponseParameters, common::DaemonErrorCode> Execute(
        const common::OperationIdentifier& operation_id,
        common::RequestParameters& request) override
    {
        ++m_execute_calls;
        m_last_operation_id = operation_id;
        m_last_execute_parameters = request;
        if (m_execute_error.has_value())
        {
            return make_unexpected(m_execute_error.value());
        }
        return m_execute_response;
    }

    /// @brief Reset the handler. Always succeeds and records nothing.
    Expected<std::monostate, common::DaemonErrorCode> Reset() override
    {
        return std::monostate{};
    }

    /// @brief Make every later `Execute` fail.
    /// @param error Error that `Execute` returns.
    void FailExecuteWith(const common::DaemonErrorCode error) noexcept
    {
        m_execute_error = error;
    }

    /// @brief Set the response parameters that a successful `Execute` returns.
    /// @param response Parameters returned to the caller of `Execute`.
    void SetExecuteResponse(common::ResponseParameters response)
    {
        m_execute_response = std::move(response);
    }

    /// @return Number of `InitializeContext` calls, whether or not they failed.
    [[nodiscard]] int InitCalls() const noexcept
    {
        return m_init_calls;
    }

    /// @return Number of `Execute` calls, whether or not they failed.
    [[nodiscard]] int ExecuteCalls() const noexcept
    {
        return m_execute_calls;
    }

    /// @return Operation passed to the latest `Execute`; default-constructed before the first call.
    [[nodiscard]] const common::OperationIdentifier& LastOperationId() const noexcept
    {
        return m_last_operation_id;
    }

    /// @return Parameters passed to the latest `Execute`; empty before the first call.
    [[nodiscard]] const common::RequestParameters& LastExecuteParameters() const noexcept
    {
        return m_last_execute_parameters;
    }

    /// @return Parameters passed to the latest `InitializeContext`; default-constructed before the
    ///         first call.
    [[nodiscard]] const provider::handler::InitializationParams& LastParams() const noexcept
    {
        return m_last_params;
    }

  private:
    std::optional<common::DaemonErrorCode> m_init_error;
    std::optional<common::DaemonErrorCode> m_execute_error;
    common::ResponseParameters m_execute_response{};
    int m_init_calls{0};
    int m_execute_calls{0};
    common::OperationIdentifier m_last_operation_id{};
    common::RequestParameters m_last_execute_parameters{};
    provider::handler::InitializationParams m_last_params{};
};

/// @brief Handler factory that creates `StubHandler`s, or fails with a configured error.
///
/// Both `CreateHandler` and `CreateKeyManagementHandler` behave the same: they count the call and
/// either fail with the configured error or create a handler. The handler type, algorithm and
/// descriptor arguments are ignored.
class StubHandlerFactory final : public provider::handler::ICryptoHandlerFactory
{
  public:
    /// @brief Create a factory whose creations succeed.
    StubHandlerFactory() = default;

    /// @brief Make every later creation fail.
    /// @param error Public error code carried by the failed result.
    void FailWith(const score::crypto::CryptoErrorCode error) noexcept
    {
        m_error = error;
    }

    /// @brief Make handlers created from now on fail their initialization.
    /// @param error Error that `InitializeContext` of each such handler returns.
    void FailHandlerInitializationWith(const common::DaemonErrorCode error) noexcept
    {
        m_handler_init_error = error;
    }

    /// @return Number of creation calls, whether or not they failed.
    [[nodiscard]] int CreateCalls() const noexcept
    {
        return m_create_calls;
    }

    /// @return Handler created by the latest successful creation, or null if none succeeded.
    [[nodiscard]] const std::shared_ptr<StubHandler>& LastHandler() const noexcept
    {
        return m_last_handler;
    }

    /// @brief Create a handler or fail as configured; the arguments are ignored.
    /// @return A new `StubHandler`, or the error set by `FailWith`.
    ::score::Result<provider::handler::Handler::Sptr> CreateHandler(
        const common::HandlerId&,
        const ::score::crypto::AlgorithmDescriptor&) override
    {
        return Create();
    }

    /// @brief Create a handler or fail as configured.
    /// @return A new `StubHandler`, or the error set by `FailWith`.
    ::score::Result<provider::handler::Handler::Sptr> CreateKeyManagementHandler() override
    {
        return Create();
    }

  private:
    ::score::Result<provider::handler::Handler::Sptr> Create()
    {
        ++m_create_calls;
        if (m_error.has_value())
        {
            return ::score::Result<provider::handler::Handler::Sptr>(::score::unexpect,
                                                                     ::score::crypto::MakeError(m_error.value()));
        }
        m_last_handler = std::make_shared<StubHandler>(m_handler_init_error);
        return ::score::Result<provider::handler::Handler::Sptr>(m_last_handler);
    }

    std::optional<score::crypto::CryptoErrorCode> m_error;
    std::optional<common::DaemonErrorCode> m_handler_init_error;
    int m_create_calls{0};
    std::shared_ptr<StubHandler> m_last_handler;
};

/// @brief Provider with configurable capabilities and a `StubHandlerFactory`.
///
/// It reports itself initialized after `Initialize`, and takes its id from the initialization
/// context. Register it with a `ProviderManager` and initialize the manager before reading
/// `GetProviderId`; the id is invalid until then.
class StubProvider final : public provider::IProvider
{
  public:
    /// @brief Create a provider.
    /// @param name Name the provider reports; use the same name when registering it.
    /// @param capabilities Capabilities the provider advertises.
    StubProvider(std::string name, common::ProviderCapability capabilities)
        : m_name{std::move(name)}, m_capabilities{capabilities}, m_factory{std::make_shared<StubHandlerFactory>()}
    {
    }

    /// @brief Take the assigned id and report the provider as initialized. Always succeeds.
    bool Initialize(const provider::ProviderInitContext& ctx) override
    {
        m_id = ctx.numeric_id;
        m_initialized = true;
        return true;
    }

    void Shutdown() override
    {
        m_initialized = false;
    }

    [[nodiscard]] bool IsInitialized() const override
    {
        return m_initialized;
    }

    /// @return The id assigned at initialization, or the invalid id before that.
    common::ProviderId GetProviderId() const override
    {
        return m_id;
    }

    const common::ProviderName& GetProviderName() const override
    {
        return m_name;
    }

    common::ProviderCapability GetProviderCapabilities() override
    {
        return m_capabilities;
    }

    /// @return The provider's `StubHandlerFactory`; the same instance every time.
    std::shared_ptr<provider::handler::ICryptoHandlerFactory> GetCryptoHandlerFactory() override
    {
        return m_factory;
    }

    /// @return The factory with its concrete type, for configuring failures and reading counts.
    [[nodiscard]] const std::shared_ptr<StubHandlerFactory>& Factory() const noexcept
    {
        return m_factory;
    }

  private:
    common::ProviderName m_name;
    common::ProviderCapability m_capabilities;
    std::shared_ptr<StubHandlerFactory> m_factory;
    common::ProviderId m_id{common::kInvalidProviderId};
    bool m_initialized{false};
};

/// @brief Data manager that forwards every call to a real `DataManager` and records node changes.
///
/// Behaviour is that of the real data manager. In addition it records the ids returned by
/// successful `addChildNode` calls and the ids passed to `deleteNode`, so a test can verify which
/// nodes a unit created and whether it removed them again. Nodes the test adds directly with
/// `addNode`, such as a connection node, are not recorded.
class RecordingDataManager final : public data_manager::IDataManager
{
  public:
    Expected<data_manager::DataNodeId, common::DaemonErrorCode> addNode(
        data_manager::ClientId client_id,
        std::shared_ptr<data_manager::DataNode> node) override
    {
        return m_inner.addNode(client_id, std::move(node));
    }

    Expected<data_manager::DataNodeId, common::DaemonErrorCode> addChildNode(
        data_manager::ClientId client_id,
        data_manager::DataNodeId parent_id,
        std::shared_ptr<data_manager::DataNode> node) override
    {
        auto result = m_inner.addChildNode(client_id, parent_id, std::move(node));
        if (result.has_value())
        {
            m_added_children.push_back(result.value());
        }
        return result;
    }

    Expected<data_manager::DataNodeId, common::DaemonErrorCode> addSiblingNode(
        data_manager::ClientId client_id,
        data_manager::DataNodeId sibling_id,
        std::shared_ptr<data_manager::DataNode> node) override
    {
        return m_inner.addSiblingNode(client_id, sibling_id, std::move(node));
    }

    Expected<std::monostate, common::DaemonErrorCode> deleteNode(data_manager::ClientId client_id,
                                                                 data_manager::DataNodeId node_id) override
    {
        m_deleted.push_back(node_id);
        return m_inner.deleteNode(client_id, node_id);
    }

    Expected<std::monostate, common::DaemonErrorCode> deleteClientNodes(data_manager::ClientId client_id) override
    {
        return m_inner.deleteClientNodes(client_id);
    }

    Expected<std::monostate, common::DaemonErrorCode> releaseNodeAccessor(
        data_manager::ClientId client_id,
        data_manager::DataNodeId node_id) const override
    {
        return m_inner.releaseNodeAccessor(client_id, node_id);
    }

    Expected<data_manager::DataNodeAccessor<data_manager::DataNode>, common::DaemonErrorCode> getNodeAccessor(
        data_manager::ClientId client_id,
        data_manager::DataNodeId node_id) const override
    {
        return m_inner.getNodeAccessor(client_id, node_id);
    }

    /// @return Ids returned by successful `addChildNode` calls, in order.
    [[nodiscard]] const std::vector<data_manager::DataNodeId>& AddedChildren() const noexcept
    {
        return m_added_children;
    }

    /// @return Ids passed to `deleteNode`, in order, whether or not the node existed.
    [[nodiscard]] const std::vector<data_manager::DataNodeId>& Deleted() const noexcept
    {
        return m_deleted;
    }

    /// @brief Check whether a node exists, without keeping access to it.
    /// @param client_id Owner of the node.
    /// @param node_id Node to look up.
    /// @return True if the node can be accessed for the client.
    [[nodiscard]] bool NodeExists(data_manager::ClientId client_id, data_manager::DataNodeId node_id) const
    {
        return m_inner.getNodeAccessor(client_id, node_id).has_value();
    }

  private:
    data_manager::DataManager m_inner;
    std::vector<data_manager::DataNodeId> m_added_children;
    std::vector<data_manager::DataNodeId> m_deleted;
};

}  // namespace score::crypto::daemon::mediator::test_doubles

#endif  // SCORE_CRYPTO_SRC_DAEMON_MEDIATOR_MEDIATOR_TEST_DOUBLES_HPP

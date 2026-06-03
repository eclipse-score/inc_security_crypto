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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_EXECUTORS_KEY_MGMT_EXECUTOR_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_EXECUTORS_KEY_MGMT_EXECUTOR_HPP

#include "score/crypto/daemon/common/types.hpp"
#include "score/crypto/daemon/key_management/core/key_management_service.hpp"
#include "score/crypto/daemon/key_management/interfaces/i_key_factory.hpp"
#include "score/crypto/daemon/key_management/interfaces/i_key_slot_handler.hpp"
#include "score/crypto/daemon/provider/executors/key_mgmt_context.hpp"

#include <memory>
#include <string>

namespace score::crypto::daemon::provider::crypto_executor
{

/// Stateless executor for key management operations.
///
/// Each provider-side handler (OpenSslKeyManagementHandler, Pkcs11KeyManagementHandler)
/// receives an instance from the factory and delegates Execute() to it.  The stable
/// collaborators (factory, slot_handler, service) are injected at construction and
/// never change; the per-context identifiers (provider_id, client_id, context_node_id)
/// are passed as a KeyMgmtExecutionContext struct.
class KeyManagementExecutor final
{
  public:
    KeyManagementExecutor(std::shared_ptr<key_management::IKeyFactory> factory,
                          std::shared_ptr<key_management::IKeySlotHandler> slot_handler,
                          std::shared_ptr<key_management::KeyManagementService> service);
    ~KeyManagementExecutor() = default;

    KeyManagementExecutor(const KeyManagementExecutor&) = delete;
    KeyManagementExecutor& operator=(const KeyManagementExecutor&) = delete;
    KeyManagementExecutor(KeyManagementExecutor&&) = delete;
    KeyManagementExecutor& operator=(KeyManagementExecutor&&) = delete;

    /// Dispatch a key management operation.
    ///
    /// @param ctx             Stable per-context parameters (provider_id, client_id, context_node_id).
    /// @param operationId     Operation and action identifiers.
    /// @param request         Packed request parameters from the client.
    [[nodiscard]] Expected<common::ResponseParameters, score::crypto::daemon::common::DaemonErrorCode> Execute(
        const KeyMgmtExecutionContext& ctx,
        const common::OperationIdentifier& operationId,
        common::RequestParameters& request);

  private:
    std::shared_ptr<key_management::IKeyFactory> m_factory;
    std::shared_ptr<key_management::IKeySlotHandler> m_slot_handler;
    std::shared_ptr<key_management::KeyManagementService> m_service;

    [[nodiscard]] Expected<common::ResponseParameters, score::crypto::daemon::common::DaemonErrorCode> HandleGenerate(
        const KeyMgmtExecutionContext& ctx,
        common::RequestParameters& request);

    [[nodiscard]] Expected<common::ResponseParameters, score::crypto::daemon::common::DaemonErrorCode> HandleLoad(
        const KeyMgmtExecutionContext& ctx,
        common::RequestParameters& request);

    [[nodiscard]] Expected<common::ResponseParameters, score::crypto::daemon::common::DaemonErrorCode> HandleRelease(
        std::uint64_t client_id,
        common::RequestParameters& request);

    [[nodiscard]] Expected<common::ResponseParameters, score::crypto::daemon::common::DaemonErrorCode> HandleSlotInfo(
        std::uint64_t client_id,
        common::RequestParameters& request);
};

}  // namespace score::crypto::daemon::provider::crypto_executor

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_EXECUTORS_KEY_MGMT_EXECUTOR_HPP

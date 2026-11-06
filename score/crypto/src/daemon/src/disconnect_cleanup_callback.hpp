/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

#ifndef SCORE_CRYPTO_SRC_DAEMON_SRC_DISCONNECT_CLEANUP_CALLBACK_HPP
#define SCORE_CRYPTO_SRC_DAEMON_SRC_DISCONNECT_CLEANUP_CALLBACK_HPP

#include "score/crypto/src/ipc/message_passing_adapter/server/server_callbacks.hpp"

#include <memory>

namespace score::crypto::daemon::data_manager
{
class IDataManager;
}  // namespace score::crypto::daemon::data_manager

namespace score::crypto::daemon::key_management
{
class KeyManagementService;
}  // namespace score::crypto::daemon::key_management

namespace score::crypto::daemon::detail
{
score::crypto::ipc::message_passing::DisconnectCleanupCallback MakeDisconnectCleanupCallback(
    std::shared_ptr<data_manager::IDataManager> data_manager,
    std::shared_ptr<key_management::KeyManagementService> key_management_service);
}  // namespace score::crypto::daemon::detail

#endif  // SCORE_CRYPTO_SRC_DAEMON_SRC_DISCONNECT_CLEANUP_CALLBACK_HPP
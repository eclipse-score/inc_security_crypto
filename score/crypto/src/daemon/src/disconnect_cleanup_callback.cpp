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

#include "score/crypto/src/daemon/src/disconnect_cleanup_callback.hpp"

#include "score/crypto/src/daemon/data_manager/i_data_manager.hpp"
#include "score/crypto/src/daemon/key_management/core/key_management_service.hpp"

#include <utility>
#include <variant>

namespace score::crypto::daemon::detail
{
score::crypto::ipc::message_passing::DisconnectCleanupCallback MakeDisconnectCleanupCallback(
    std::shared_ptr<data_manager::IDataManager> data_manager,
    std::shared_ptr<key_management::KeyManagementService> key_management_service)
{
    // Using the lambda capture to hold shared pointers to the data manager and key management service
    // to ensure liftime
    return [data_manager = std::move(data_manager), key_management_service = std::move(key_management_service)](
               const score::crypto::daemon::control_plane::protocol::ClientId client_id) {
        score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> first_failure{};
        if (data_manager)
        {
            auto result = data_manager->deleteClientNodes(client_id, true);
            if (first_failure.has_value())
            {
                first_failure = result;
            }
        }
        if (key_management_service)
        {
            key_management_service->CleanupClient(client_id);
        }

        return first_failure;
    };
}
}  // namespace score::crypto::daemon::detail

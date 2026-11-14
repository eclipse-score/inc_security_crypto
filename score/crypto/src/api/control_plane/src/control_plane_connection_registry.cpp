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

#include "score/crypto/src/api/control_plane/src/control_plane_connection_registry.hpp"
#include "score/crypto/src/ipc/message_passing_adapter/client/message_passing_control_client.h"

#include <utility>

namespace score::crypto::api::control_plane
{

ControlPlaneConnectionRegistry& ControlPlaneConnectionRegistry::Instance() noexcept
{
    static ControlPlaneConnectionRegistry instance;
    return instance;
}

ControlPlaneConnectionRegistry::Result ControlPlaneConnectionRegistry::EstablishConnection(
    const std::string_view service_identifier)
{
    const std::string registry_key{service_identifier};
    std::shared_ptr<std::mutex> establishment_mutex;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto& mutex_entry = m_establishment_mutexes[registry_key];
        if (mutex_entry == nullptr)
        {
            mutex_entry = std::make_shared<std::mutex>();
        }
        establishment_mutex = mutex_entry;
    }

    std::lock_guard<std::mutex> establishment_lock(*establishment_mutex);
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto iterator = m_connections.find(registry_key);
        if (iterator != m_connections.end())
        {
            auto connection = iterator->second.lock();
            if (connection != nullptr)
            {
                return connection;
            }
            m_connections.erase(iterator);
        }
    }

    auto control_client_result = score::crypto::ipc::message_passing::MessagePassingControlClient::Create(registry_key);
    if (!control_client_result.has_value())
    {
        return score::crypto::make_unexpected(control_client_result.error());
    }

    auto connection = std::make_shared<ControlPlaneConnection>(std::move(control_client_result.value()));
    const auto establish_result = connection->Establish();
    if (!establish_result.has_value())
    {
        return score::crypto::make_unexpected(establish_result.error());
    }
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_connections[registry_key] = connection;
    }
    return connection;
}

}  // namespace score::crypto::api::control_plane

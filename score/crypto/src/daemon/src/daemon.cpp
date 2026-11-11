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

#include "score/mw/log/logging.h"
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>

#include <memory>
#include <thread>
#include <utility>

#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/config/inc/config.hpp"
#include "score/crypto/src/daemon/control_plane/basic_handler_chain_factory.hpp"
#include "score/crypto/src/daemon/control_plane/i_control_server.h"
#include "score/crypto/src/daemon/data_manager/data_manager.hpp"
#include "score/crypto/src/daemon/key_management/key_management_module.hpp"
#include "score/crypto/src/daemon/provider/provider_manager_factory.hpp"
#include "score/crypto/src/daemon/src/disconnect_cleanup_callback.hpp"
#include "score/crypto/src/ipc/message_passing_adapter/server/message_passing_control_server.h"

namespace score::crypto::daemon
{

static std::atomic<bool> g_shutdown_requested{false};

void SignalHandler(int signal)
{
    g_shutdown_requested.store(true);
}

void SetupSignalHandlers()
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SignalHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGINT, &sa, nullptr);   // Ctrl+C
    sigaction(SIGTERM, &sa, nullptr);  // kill
}

}  // namespace score::crypto::daemon

int main(int argc, char** argv)
{
    // Create and configure the daemon
    score::crypto::daemon::config::Config config;

    // Parse configuration from multiple sources (priority: file < env < cmdline).
    // A missing config file leaves every section absent; a present but invalid one stops startup.
    if (!config.ParseConfig())
    {
        score::mw::log::LogError() << "Failed to load crypto stack configuration; refusing to start";
        return 1;
    }

    // Create and initialize the provider manager via factory.
    auto provider_manager_result = score::crypto::daemon::provider::ProviderManagerFactory::Create(config);
    if (!provider_manager_result.has_value())
    {
        score::mw::log::LogError() << "Failed to create provider manager"
                                   << " (error code: " << static_cast<int>(provider_manager_result.error()) << ")";
        return 1;
    }
    auto provider_manager = std::move(*provider_manager_result);

    // Create data manager
    auto data_manager = std::make_shared<score::crypto::daemon::data_manager::DataManager>();

    // Initialize key management subsystem. An absent key section yields an empty
    // config; the module decides what that means for its operations.
    auto key_mgmt_module = score::crypto::daemon::key_management::KeyManagementModule::Create(
        data_manager, provider_manager, config.GetKeyConfig());

    // Set HandlerChainFactory to be used by IControlServer
    auto handler_factory = std::make_unique<score::crypto::daemon::control_plane::BasicHandlerChainFactory>(
        data_manager,                                              // Shared thread-safe data manager
        provider_manager,                                          // Shared thread-safe provider manager
        config,                                                    // Config by reference (outlives factory)
        key_mgmt_module ? key_mgmt_module->GetService() : nullptr  // Key management service
    );

    using MessagePassingServer = score::crypto::ipc::message_passing::MessagePassingControlServer;

    // TODO: Implement proper authorization callback for the control server.
    MessagePassingServer::AuthorizationCallback authorization = [](std::uint32_t, std::uint32_t) {
        return score::crypto::Expected<bool, score::crypto::daemon::common::DaemonErrorCode>{true};
    };
    const auto key_management_service = key_mgmt_module ? key_mgmt_module->GetService() : nullptr;
    auto cleanup_callback =
        score::crypto::daemon::detail::MakeDisconnectCleanupCallback(data_manager, key_management_service);

    auto server_result = MessagePassingServer::Create(
        std::move(handler_factory), config.GetIPCConfig(), std::move(authorization), std::move(cleanup_callback));
    if (!server_result.has_value())
    {
        score::mw::log::LogError() << "Failed to create crypto control server";
        return 1;
    }
    std::unique_ptr<score::crypto::daemon::control_plane::IControlServer> server = std::move(server_result).value();

    score::crypto::daemon::SetupSignalHandlers();

    // Start is synchronous: a successful result means that the server is listening.
    const auto start_result = server->Start();
    if (!start_result.has_value())
    {
        score::mw::log::LogError() << "Failed to start crypto control server"
                                   << " (error code: " << static_cast<int>(start_result.error()) << ")";
        return 1;
    }

    // Main daemon loop - wait for shutdown signal
    while (!score::crypto::daemon::g_shutdown_requested.load())
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // Shutdown sequence
    score::mw::log::LogDebug() << "Termination requested, shutting down daemon...";
    server->Stop();
    server->WaitForTermination();
    server.reset();

    return 0;
}

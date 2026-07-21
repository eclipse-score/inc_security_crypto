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
#include <cstring>

#include <memory>
#include <thread>

#include "score/crypto/daemon/config/inc/config.hpp"
#include "score/crypto/daemon/control_plane/basic_handler_chain_factory.hpp"
#include "score/crypto/daemon/control_plane/i_control_server.h"
#include "score/crypto/daemon/data_manager/data_manager.hpp"
#include "score/crypto/daemon/key_management/key_management_module.hpp"
#include "score/crypto/daemon/provider/pkcs11/pkcs11_module.hpp"
#include "score/crypto/daemon/provider/pkcs11/pkcs11_provider_factory.hpp"
#include "score/crypto/daemon/provider/provider_manager.hpp"
#include "score/crypto/daemon/provider/score_provider/score_provider_factory.hpp"
#include "score/crypto/ipc/grpc_adapter/grpc_control_server.h"
#include "score/crypto/ipc/ipc_config.h"

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

    // Parse configuration from multiple sources (priority: file < env < cmdline)
    if (!config.ParseConfig())
    {
        score::mw::log::LogError() << "Warning: Could not parse config file (may not exist)";
    }

    auto provider_manager = std::make_shared<score::crypto::daemon::provider::ProviderManager>(config);

    // Wire provider factories — each factory encapsulates construction and registration
    // of one or more providers.  Factories are called in order during Initialize().

    // Score provider factory (OpenSSL software provider)
    config.GetScoreProviderConfig().PopulateDefaults();
    auto score_factory = std::make_unique<score::crypto::daemon::provider::score_provider::ScoreProviderFactory>();
    config.GetScoreProviderConfig().Configure(*score_factory);
    provider_manager->RegisterFactory(std::move(score_factory));

    // Populate production PKCS#11 default tokens (SoftHSM) unless the config
    // file already supplied entries.
    config.GetPkcs11Config().PopulateDefaults();

    // Pkcs11Config visits the factory: converts Pkcs11TokenEntry entries to
    // Pkcs11ProviderConfig and calls factory.SetTokenConfigs() internally.
    auto pkcs11_factory = std::make_unique<score::crypto::daemon::provider::pkcs11::Pkcs11ProviderFactory>();
    config.GetPkcs11Config().Configure(*pkcs11_factory);
    provider_manager->RegisterFactory(std::move(pkcs11_factory));

    provider_manager->Initialize();

    // Create data manager
    auto data_manager = std::make_shared<score::crypto::daemon::data_manager::DataManager>();

    // Initialize key management subsystem
    auto key_mgmt_module = score::crypto::daemon::key_management::KeyManagementModule::Create(
        data_manager, provider_manager, config.GetKeyConfig());

    // Set HandlerChainFactory to be used by IControlServer
    auto handler_factory = std::make_unique<score::crypto::daemon::control_plane::BasicHandlerChainFactory>(
        data_manager,                                              // Shared thread-safe data manager
        provider_manager,                                          // Shared thread-safe provider manager
        config,                                                    // Config by reference (outlives factory)
        key_mgmt_module ? key_mgmt_module->GetService() : nullptr  // Key management service
    );

    std::unique_ptr<score::crypto::daemon::control_plane::IControlServer> server =
        std::make_unique<score::crypto::ipc::GrpcControlServer>(std::move(handler_factory));

    score::crypto::daemon::SetupSignalHandlers();

    // Start server in background thread
    std::thread server_thread([&server]() {
        server->Start(score::crypto::ipc::kControlSocket);
        server->WaitForTermination();
    });

    // Main daemon loop - wait for shutdown signal
    while (!score::crypto::daemon::g_shutdown_requested.load())
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // Shutdown sequence
    score::mw::log::LogDebug() << "Termination requested, shutting down daemon...";
    server->Stop();
    server_thread.join();

    score::mw::log::LogDebug() << "Daemon shutdown complete";
    return 0;
}

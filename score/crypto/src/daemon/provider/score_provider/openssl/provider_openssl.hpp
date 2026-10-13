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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_PROVIDER_OPENSSL_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_PROVIDER_OPENSSL_HPP

#include <memory>

#include "score/crypto/src/daemon/provider/score_provider/score_provider.hpp"

namespace score::crypto::daemon::provider::score_provider::openssl
{

/// @brief OpenSSL software-only crypto provider.
///
/// Inherits ScoreProvider for lifecycle and lazy factory creation.
/// Adds OpenSSL-specific initialization (OPENSSL_init_crypto) and
/// key management (in-process key generation/import/release with optional
/// file-backed persistence via FileBackedSlotHandler).
class OpenSSL final : public ::score::crypto::daemon::provider::score_provider::ScoreProvider
{
  public:
    OpenSSL();
    ~OpenSSL() override;

    OpenSSL(const OpenSSL&) = delete;
    OpenSSL& operator=(const OpenSSL&) = delete;
    OpenSSL(OpenSSL&&) = delete;
    OpenSSL& operator=(OpenSSL&&) = delete;

    // --- IProvider lifecycle (OpenSSL-specific) ---
    void Shutdown() override;

    // --- Capability advertisement ---
    [[nodiscard]] common::ProviderCapability GetProviderCapabilities() override;

    // --- Key management capability ---
    std::shared_ptr<key_management::IKeyFactory> GetKeyFactory() override;
    std::shared_ptr<key_management::IKeySlotHandler> GetKeySlotHandler(
        const key_management::KeySlotConfig& config) override;
    void SetKeyManagementService(std::shared_ptr<key_management::KeyManagementService> service) override;

    // --- SHM capability ---
    std::shared_ptr<data_plane::IShmFactory> GetShmFactory() override;

  private:
    /// Performs OpenSSL-specific startup: calls OPENSSL_init_crypto and creates the key factory.
    [[nodiscard]] bool InitialiseBackend(const ProviderInitContext& ctx) override;

    /// Creates the OpenSSL-specific handler factory.
    [[nodiscard]] std::shared_ptr<::score::crypto::daemon::provider::handler::ICryptoHandlerFactory>
    CreateHandlerFactory() override;

    std::shared_ptr<key_management::IKeyFactory> m_factory;
    std::shared_ptr<key_management::KeyManagementService> m_keyManagementService;
    std::shared_ptr<data_plane::IShmFactory> m_shm_factory;
};

}  // namespace score::crypto::daemon::provider::score_provider::openssl

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_PROVIDER_OPENSSL_HPP

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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_OPERATIONS_KEY_MANAGEMENT_PKCS11_KEY_MANAGEMENT_HANDLER_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_OPERATIONS_KEY_MANAGEMENT_PKCS11_KEY_MANAGEMENT_HANDLER_HPP

#include "score/crypto/daemon/key_management/core/key_management_service.hpp"
#include "score/crypto/daemon/key_management/interfaces/i_key_factory.hpp"
#include "score/crypto/daemon/key_management/interfaces/i_key_slot_handler.hpp"
#include "score/crypto/daemon/key_management/interfaces/key_slot_config.hpp"
#include "score/crypto/daemon/provider/executors/key_mgmt_context.hpp"
#include "score/crypto/daemon/provider/executors/key_mgmt_executor.hpp"
#include "score/crypto/daemon/provider/handler/i_handler.hpp"

#include <cryptoki.h>
#include <pkcs11.h>

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>

namespace score::crypto::daemon::provider::pkcs11
{

class Pkcs11Provider;

/// PKCS#11 key management handler implementing only the Handler dispatch interface.
///
/// Implements the Handler dispatch interface (via Execute → KeyManagementExecutor).
/// The IKeyFactory implementation is delegated to a separate Pkcs11KeyFactory instance.
/// The opaque-id map (m_keys) is delegated to separate Pkcs11KeyStore instance.
///
/// This stripped-down handler focuses solely on operation dispatch for key management
/// operations: KEY_GENERATE, KEY_LOAD, KEY_RELEASE, KEY_SLOT_INFO, etc.
///
/// ### Thread safety
///   m_factory and m_slot_handler are immutable after construction (final pointers).
///
/// ### Design
///   - Pkcs11KeyFactory (injected) : handles GenerateKey and ImportKey
///   - Pkcs11KeyStore : handles opaque-id map and key release
///   - Pkcs11KeyManagementHandler : dispatch only
class Pkcs11KeyManagementHandler final : public handler::Handler
{
  public:
    Pkcs11KeyManagementHandler(std::shared_ptr<Pkcs11Provider> provider,
                               std::unique_ptr<crypto_executor::KeyManagementExecutor> executor,
                               common::ProviderId provider_id);
    ~Pkcs11KeyManagementHandler() override = default;

    Pkcs11KeyManagementHandler(const Pkcs11KeyManagementHandler&) = delete;
    Pkcs11KeyManagementHandler& operator=(const Pkcs11KeyManagementHandler&) = delete;
    Pkcs11KeyManagementHandler(Pkcs11KeyManagementHandler&&) = delete;
    Pkcs11KeyManagementHandler& operator=(Pkcs11KeyManagementHandler&&) = delete;

    // ------------------------------------------------------------------
    // Handler interface
    // ------------------------------------------------------------------

    /// No-op: all context is injected at construction.
    [[nodiscard]] Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> InitializeContext(
        const handler::InitializationParams& init_params) override;

    /// Dispatch key management operations via the shared executor.
    ///
    /// Handled: KEY_GENERATE, KEY_LOAD, KEY_RELEASE, KEY_SLOT_INFO,
    ///          KEY_WRAP, KEY_UNWRAP, KEY_DERIVE (stubs)
    [[nodiscard]] Expected<common::ResponseParameters, score::crypto::daemon::common::DaemonErrorCode> Execute(
        const common::OperationIdentifier& operationId,
        common::RequestParameters& request) override;

    [[nodiscard]] Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Reset() override;

    /// @brief Check if the given algorithm is supported by this handler.
    [[nodiscard]] static bool IsAlgorithmSupported(const common::AlgorithmId& algorithm) noexcept;

  private:
    std::shared_ptr<Pkcs11Provider> m_provider;
    std::unique_ptr<crypto_executor::KeyManagementExecutor> m_executor;
    crypto_executor::KeyMgmtExecutionContext m_ctx;

    static constexpr std::string_view LOG_PREFIX = "[PKCS11_KEY_MGMT_HANDLER]";
};

}  // namespace score::crypto::daemon::provider::pkcs11

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_OPERATIONS_KEY_MANAGEMENT_PKCS11_KEY_MANAGEMENT_HANDLER_HPP

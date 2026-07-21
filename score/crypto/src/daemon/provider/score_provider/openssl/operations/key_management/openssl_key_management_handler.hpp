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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_KEY_MANAGEMENT_HANDLER_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_KEY_MANAGEMENT_HANDLER_HPP

#include "score/crypto/daemon/provider/executors/key_mgmt_executor.hpp"
#include "score/crypto/daemon/provider/score_provider/operations/key_management/score_key_management_handler.hpp"

#include <memory>

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{

/// OpenSSL-specific key management handler.
/// Currently delegates entirely to ScoreKeyManagementHandler base.
class OpenSslKeyManagementHandler final
    : public ::score::crypto::daemon::provider::score_provider::operations::key_management::ScoreKeyManagementHandler
{
  public:
    explicit OpenSslKeyManagementHandler(std::unique_ptr<crypto_executor::KeyManagementExecutor> executor);
    ~OpenSslKeyManagementHandler() override = default;

    OpenSslKeyManagementHandler(const OpenSslKeyManagementHandler&) = delete;
    OpenSslKeyManagementHandler& operator=(const OpenSslKeyManagementHandler&) = delete;
    OpenSslKeyManagementHandler(OpenSslKeyManagementHandler&&) = delete;
    OpenSslKeyManagementHandler& operator=(OpenSslKeyManagementHandler&&) = delete;
};

}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_KEY_MANAGEMENT_HANDLER_HPP

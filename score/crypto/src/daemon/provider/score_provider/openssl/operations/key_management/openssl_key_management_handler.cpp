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

#include "score/crypto/daemon/provider/score_provider/openssl/operations/key_management/openssl_key_management_handler.hpp"

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{

OpenSslKeyManagementHandler::OpenSslKeyManagementHandler(
    std::unique_ptr<crypto_executor::KeyManagementExecutor> executor)
    : ScoreKeyManagementHandler{std::move(executor)}
{
}

}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler

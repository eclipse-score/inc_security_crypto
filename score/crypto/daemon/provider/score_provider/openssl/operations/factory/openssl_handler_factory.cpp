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

#include "score/crypto/daemon/provider/score_provider/openssl/operations/factory/openssl_handler_factory.hpp"
#include "score/crypto/daemon/common/daemon_error.hpp"
#include "score/crypto/daemon/provider/executors/key_mgmt_executor.hpp"
#include "score/crypto/daemon/provider/score_provider/openssl/operations/hash/openssl_hash_handler.hpp"
#include "score/crypto/daemon/provider/score_provider/openssl/operations/key_management/openssl_key_management_handler.hpp"
#include "score/crypto/daemon/provider/score_provider/openssl/operations/mac/openssl_hmac_handler.hpp"
#include "score/crypto/daemon/provider/score_provider/operations/hash/hash_executor.hpp"
#include "score/crypto/daemon/provider/score_provider/operations/mac/mac_executor.hpp"
#include "score/result/result.h"

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{

using HandlerSptr = ::score::crypto::daemon::provider::handler::Handler::Sptr;

OpenSslHandlerFactory::OpenSslHandlerFactory(std::shared_ptr<key_management::IKeyFactory> km_handler,
                                             std::shared_ptr<key_management::IKeySlotHandler> slot_handler,
                                             key_management::KeyManagementService::Sptr km_service)
    : ScoreHandlerFactory{std::move(km_handler), std::move(slot_handler), std::move(km_service)}
{
}

score::Result<HandlerSptr> OpenSslHandlerFactory::CreateHashHandler(const common::AlgorithmId& algorithm)
{
    if (!OpenSslHashHandler::IsAlgorithmSupported(algorithm))
    {
        score::result::Error error(
            static_cast<score::result::ErrorCode>(score::mw::crypto::CryptoErrorCode::kUnsupportedAlgorithm),
            score::mw::crypto::kCryptoErrorDomain,
            "Algorithm not supported for handler: " + algorithm);
        return score::Result<HandlerSptr>(score::unexpect, error);
    }
    auto hash_executor = std::make_unique<operations::hash::HashExecutor>();
    return std::make_shared<OpenSslHashHandler>(std::move(hash_executor), algorithm);
}

score::Result<HandlerSptr> OpenSslHandlerFactory::CreateMacHandler(const common::AlgorithmId& algorithm)
{
    if (!OpenSslHmacHandler::IsAlgorithmSupported(algorithm))
    {
        score::result::Error error(
            static_cast<score::result::ErrorCode>(score::mw::crypto::CryptoErrorCode::kUnsupportedAlgorithm),
            score::mw::crypto::kCryptoErrorDomain,
            "Algorithm not supported for handler: " + algorithm);
        return score::Result<HandlerSptr>(score::unexpect, error);
    }
    auto mac_executor = std::make_unique<operations::mac::MacExecutor>();
    return std::make_shared<OpenSslHmacHandler>(std::move(mac_executor), algorithm);
}

score::Result<HandlerSptr> OpenSslHandlerFactory::CreateKeyManagementHandler()
{
    auto executor =
        std::make_unique<crypto_executor::KeyManagementExecutor>(m_key_factory, m_slot_handler, m_km_service);
    return std::make_shared<OpenSslKeyManagementHandler>(std::move(executor));
}

}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler

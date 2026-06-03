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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_FACTORY_SCORE_HANDLER_FACTORY_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_FACTORY_SCORE_HANDLER_FACTORY_HPP

#include "score/crypto/daemon/common/types.hpp"
#include "score/crypto/daemon/key_management/core/key_management_service.hpp"
#include "score/crypto/daemon/key_management/interfaces/i_key_factory.hpp"
#include "score/crypto/daemon/key_management/interfaces/i_key_slot_handler.hpp"
#include "score/crypto/daemon/provider/handler/i_crypto_handler_factory.hpp"
#include "score/result/result.h"

#include <memory>

namespace score::crypto::daemon::provider::score_provider::operations::factory
{

/// @brief Abstract base handler factory for the score interface family.
///
/// Implements the daemon's ICryptoHandlerFactory by dispatching CreateHandler
/// requests to protected virtual factory methods. Concrete score providers
/// (e.g. OpenSSL) inherit and override the factory methods to create their
/// provider-specific handlers.
///
/// Default factory methods return kUnsupportedOperation so that a provider
/// need only implement the operations it supports.
class ScoreHandlerFactory : public handler::ICryptoHandlerFactory
{
  public:
    ScoreHandlerFactory(std::shared_ptr<key_management::IKeyFactory> key_factory,
                        std::shared_ptr<key_management::IKeySlotHandler> slot_handler,
                        key_management::KeyManagementService::Sptr km_service);

    ~ScoreHandlerFactory() override = default;

    /// Routes to CreateHashHandler, CreateMacHandler, or CreateKeyManagementHandler.
    ::score::Result<handler::Handler::Sptr> CreateHandler(const common::HandlerId& handlerId,
                                                          const common::AlgorithmId& algorithm) override;

  protected:
    /// Override in concrete provider to create a hash handler. Default returns unsupported.
    [[nodiscard]] virtual ::score::Result<handler::Handler::Sptr> CreateHashHandler(
        const common::AlgorithmId& algorithm);

    /// Override in concrete provider to create a MAC handler. Default returns unsupported.
    [[nodiscard]] virtual ::score::Result<handler::Handler::Sptr> CreateMacHandler(
        const common::AlgorithmId& algorithm);

    /// Override in concrete provider to create a key management handler. Default returns unsupported.
    [[nodiscard]] virtual ::score::Result<handler::Handler::Sptr> CreateKeyManagementHandler();

    std::shared_ptr<key_management::IKeyFactory> m_key_factory;
    std::shared_ptr<key_management::IKeySlotHandler> m_slot_handler;
    key_management::KeyManagementService::Sptr m_km_service;

  private:
    static constexpr const char* HASH = "HASH";
    static constexpr const char* MAC = "MAC";
    static constexpr const char* KEY_MANAGEMENT = "KEY_MANAGEMENT";
};

}  // namespace score::crypto::daemon::provider::score_provider::operations::factory

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_FACTORY_SCORE_HANDLER_FACTORY_HPP

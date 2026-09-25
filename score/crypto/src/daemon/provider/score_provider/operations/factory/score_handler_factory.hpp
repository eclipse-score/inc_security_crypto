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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_FACTORY_SCORE_HANDLER_FACTORY_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_FACTORY_SCORE_HANDLER_FACTORY_HPP

#include "score/crypto/src/daemon/common/context_types.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/key_management/core/key_management_service.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/i_key_factory.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/i_key_slot_handler.hpp"
#include "score/crypto/src/daemon/provider/handler/i_crypto_handler_factory.hpp"
#include "score/result/result.h"

#include <memory>
#include <string_view>

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

    /// Override in concrete provider to create a symmetric cipher handler. Default returns unsupported.
    [[nodiscard]] virtual ::score::Result<handler::Handler::Sptr> CreateCipherHandler(
        const common::AlgorithmId& algorithm);

    /// Override in concrete provider to create a signature handler.
    ///
    /// Serves both the SIGN and VERIFY context types: the direction is carried
    /// in the OperationMode parameter of CTX_CREATE, not in the handler id, so
    /// one implementation covers both. Default returns unsupported.
    [[nodiscard]] virtual ::score::Result<handler::Handler::Sptr> CreateSignatureHandler(
        const common::AlgorithmId& algorithm);

    /// Override in concrete provider to create a random handler. Default returns unsupported.
    [[nodiscard]] virtual ::score::Result<handler::Handler::Sptr> CreateRandomHandler(
        const common::AlgorithmId& algorithm);

    std::shared_ptr<key_management::IKeyFactory> m_key_factory;
    std::shared_ptr<key_management::IKeySlotHandler> m_slot_handler;
    key_management::KeyManagementService::Sptr m_km_service;

  private:
    // The context-type ids are shared with the client and the mediator, which
    // dispatches on the same strings — see common/context_types.hpp.
    static constexpr std::string_view HASH = common::context_types::kHash;
    static constexpr std::string_view MAC = common::context_types::kMac;
    static constexpr std::string_view KEY_MANAGEMENT = common::context_types::kKeyManagement;
    static constexpr std::string_view CIPHER = common::context_types::kCipher;
    static constexpr std::string_view SIGN = common::context_types::kSign;
    static constexpr std::string_view VERIFY = common::context_types::kVerify;
    static constexpr std::string_view RANDOM = common::context_types::kRandom;
};

}  // namespace score::crypto::daemon::provider::score_provider::operations::factory

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_FACTORY_SCORE_HANDLER_FACTORY_HPP

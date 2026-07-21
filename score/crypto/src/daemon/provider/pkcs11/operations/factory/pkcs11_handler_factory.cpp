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

#include "score/crypto/daemon/provider/pkcs11/operations/factory/pkcs11_handler_factory.hpp"

// Full Pkcs11Provider definition required here (forward-declared in the header)
// to call AcquireSession / ReleaseSession.
#include "score/crypto/daemon/provider/pkcs11/pkcs11_provider.hpp"
#include "score/crypto/daemon/provider/pkcs11/pkcs11_session_guard.hpp"

#include "score/crypto/common/types.hpp"
#include "score/crypto/daemon/common/daemon_error.hpp"
#include "score/crypto/daemon/provider/executors/key_mgmt_executor.hpp"
#include "score/crypto/daemon/provider/pkcs11/operations/hash/pkcs11_hash_executor.hpp"
#include "score/crypto/daemon/provider/pkcs11/operations/hash/pkcs11_hash_handler.hpp"
#include "score/crypto/daemon/provider/pkcs11/operations/key_management/pkcs11_key_management_handler.hpp"
#include "score/crypto/daemon/provider/pkcs11/operations/mac/pkcs11_mac_executor.hpp"
#include "score/crypto/daemon/provider/pkcs11/operations/mac/pkcs11_mac_handler.hpp"

#include "score/mw/log/logging.h"

namespace score::crypto::daemon::provider::pkcs11
{

Pkcs11HandlerFactory::Pkcs11HandlerFactory(const Pkcs11Module& module, Pkcs11Provider& provider) noexcept
    : m_module{module}, m_provider{provider}
{
}

score::Result<handler::Handler::Sptr> Pkcs11HandlerFactory::CreateHandler(const common::HandlerId& handlerId,
                                                                          const common::AlgorithmId& algorithm)
{
    if (handlerId == kHashHandlerId)
    {
        return CreateHashHandler(algorithm);
    }

    if (handlerId == kMacHandlerId)
    {
        return CreateMacHandler(algorithm);
    }

    if (handlerId == kKeyManagementHandlerId)
    {
        return CreateKeyManagementHandler();
    }

    const score::result::Error error(
        static_cast<score::result::ErrorCode>(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation),
        score::mw::crypto::kCryptoErrorDomain,
        "Handler not supported by PKCS#11 provider: " + handlerId);
    return score::Result<handler::Handler::Sptr>(score::unexpect, error);
}

score::Result<handler::Handler::Sptr> Pkcs11HandlerFactory::CreateHashHandler(const common::AlgorithmId& algorithm)
{
    if (!Pkcs11HashHandler::IsAlgorithmSupported(algorithm))
    {
        const score::result::Error error(static_cast<score::result::ErrorCode>(
                                             score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm),
                                         score::mw::crypto::kCryptoErrorDomain,
                                         "Algorithm not supported for PKCS#11 hash handler: " + algorithm);
        return score::Result<handler::Handler::Sptr>(score::unexpect, error);
    }

    score::mw::log::LogDebug() << "[PKCS11_HANDLER_FACTORY] Creating HASH handler for algorithm:" << algorithm;

    Pkcs11SessionGuard guard(m_provider, Pkcs11HashHandler::kRequirements);
    if (!guard)
    {
        const score::result::Error error(static_cast<score::result::ErrorCode>(guard.error()),
                                         score::mw::crypto::kCryptoErrorDomain,
                                         "PKCS#11: failed to acquire session for handler");
        return score::Result<handler::Handler::Sptr>(score::unexpect, error);
    }

    auto executor = std::make_unique<Pkcs11HashExecutor>(m_module);
    auto handler = std::make_shared<Pkcs11HashHandler>(std::move(executor), guard.get(), algorithm, &m_provider);
    static_cast<void>(guard.release());
    return handler;
}

score::Result<handler::Handler::Sptr> Pkcs11HandlerFactory::CreateMacHandler(const common::AlgorithmId& algorithm)
{
    if (!Pkcs11MacHandler::IsAlgorithmSupported(algorithm))
    {
        const score::result::Error error(static_cast<score::result::ErrorCode>(
                                             score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm),
                                         score::mw::crypto::kCryptoErrorDomain,
                                         "Algorithm not supported for PKCS#11 MAC handler: " + algorithm);
        return score::Result<handler::Handler::Sptr>(score::unexpect, error);
    }

    Pkcs11SessionGuard guard(m_provider, Pkcs11MacHandler::kRequirements);
    if (!guard)
    {
        const score::result::Error error(static_cast<score::result::ErrorCode>(guard.error()),
                                         score::mw::crypto::kCryptoErrorDomain,
                                         "PKCS#11: failed to acquire session for MAC handler");
        return score::Result<handler::Handler::Sptr>(score::unexpect, error);
    }

    auto mac_executor = std::make_unique<Pkcs11MacExecutor>(m_module);
    auto handler = std::shared_ptr<Pkcs11MacHandler>(
        new Pkcs11MacHandler(std::move(mac_executor), m_module, guard.get(), algorithm, &m_provider));
    static_cast<void>(guard.release());
    return handler;
}

score::Result<handler::Handler::Sptr> Pkcs11HandlerFactory::CreateKeyManagementHandler()
{
    auto km_service = m_provider.GetKeyManagementService();
    if (!km_service)
    {
        const score::result::Error error(
            static_cast<score::result::ErrorCode>(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument),
            score::mw::crypto::kCryptoErrorDomain,
            "PKCS#11 key management handler requires KeyManagementService");
        return score::Result<handler::Handler::Sptr>(score::unexpect, error);
    }

    auto slot_handler = m_provider.GetKeySlotHandler(key_management::KeySlotConfig{});
    auto key_factory = m_provider.GetKeyFactory();
    auto executor = std::make_unique<crypto_executor::KeyManagementExecutor>(key_factory, slot_handler, km_service);
    auto km_handler = std::make_shared<Pkcs11KeyManagementHandler>(
        m_provider.shared_from_this(), std::move(executor), m_provider.GetProviderId());
    return km_handler;
}

}  // namespace score::crypto::daemon::provider::pkcs11

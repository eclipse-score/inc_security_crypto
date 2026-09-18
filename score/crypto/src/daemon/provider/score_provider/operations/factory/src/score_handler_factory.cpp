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

#include "score/crypto/src/daemon/provider/score_provider/operations/factory/score_handler_factory.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/result/result.h"

namespace score::crypto::daemon::provider::score_provider::operations::factory
{

ScoreHandlerFactory::ScoreHandlerFactory(
    std::shared_ptr<key_management::IKeyFactory> key_factory,
    std::shared_ptr<key_management::IKeySlotHandler> slot_handler,
    key_management::KeyManagementService::Sptr km_service,
    std::shared_ptr<::score::crypto::daemon::provider::cert_management::ICertParser> cert_parser,
    ::score::crypto::daemon::cert_management::CertManagementService::Sptr cert_service)
    : m_key_factory{std::move(key_factory)},
      m_slot_handler{std::move(slot_handler)},
      m_km_service{std::move(km_service)},
      m_cert_parser{std::move(cert_parser)},
      m_cert_service{std::move(cert_service)}
{
}

::score::Result<handler::Handler::Sptr> ScoreHandlerFactory::CreateHandler(const common::HandlerId& handlerId,
                                                                           const common::AlgorithmId& algorithm)
{
    if (handlerId == HASH)
    {
        return CreateHashHandler(algorithm);
    }
    if (handlerId == MAC)
    {
        return CreateMacHandler(algorithm);
    }
    if (handlerId == KEY_MANAGEMENT)
    {
        return CreateKeyManagementHandler();
    }
    if (handlerId == CERT_MANAGEMENT)
    {
        return CreateCertManagementHandler();
    }
    if (handlerId == CERT_VERIFICATION)
    {
        return CreateCertVerificationHandler();
    }
    if (handlerId == CERT_CSR_GENERATION)
    {
        return CreateCsrGenerationHandler();
    }
    if (handlerId == CERT_TRUST_STORE)
    {
        return CreateTrustStoreManagementHandler();
    }

    ::score::result::Error error(
        static_cast<::score::result::ErrorCode>(::score::crypto::CryptoErrorCode::kUnsupportedOperation),
        ::score::crypto::kCryptoErrorDomain,
        "Handler not supported: " + handlerId);
    return ::score::Result<handler::Handler::Sptr>(::score::unexpect, error);
}

// ---------------------------------------------------------------------------
// Default implementations — return unsupported
// ---------------------------------------------------------------------------

::score::Result<handler::Handler::Sptr> ScoreHandlerFactory::CreateHashHandler(const common::AlgorithmId& /*algorithm*/)
{
    ::score::result::Error error(
        static_cast<::score::result::ErrorCode>(::score::crypto::CryptoErrorCode::kUnsupportedOperation),
        ::score::crypto::kCryptoErrorDomain,
        "Hash handler not supported by this score provider");
    return ::score::Result<handler::Handler::Sptr>(::score::unexpect, error);
}

::score::Result<handler::Handler::Sptr> ScoreHandlerFactory::CreateMacHandler(const common::AlgorithmId& /*algorithm*/)
{
    ::score::result::Error error(
        static_cast<::score::result::ErrorCode>(::score::crypto::CryptoErrorCode::kUnsupportedOperation),
        ::score::crypto::kCryptoErrorDomain,
        "MAC handler not supported by this score provider");
    return ::score::Result<handler::Handler::Sptr>(::score::unexpect, error);
}

::score::Result<handler::Handler::Sptr> ScoreHandlerFactory::CreateKeyManagementHandler()
{
    ::score::result::Error error(
        static_cast<::score::result::ErrorCode>(::score::crypto::CryptoErrorCode::kUnsupportedOperation),
        ::score::crypto::kCryptoErrorDomain,
        "Key management handler not supported by this score provider");
    return ::score::Result<handler::Handler::Sptr>(::score::unexpect, error);
}

::score::Result<handler::Handler::Sptr> ScoreHandlerFactory::CreateCertManagementHandler()
{
    ::score::result::Error error(
        static_cast<::score::result::ErrorCode>(::score::crypto::CryptoErrorCode::kUnsupportedOperation),
        ::score::crypto::kCryptoErrorDomain,
        "Certificate management handler not supported by this score provider");
    return ::score::Result<handler::Handler::Sptr>(::score::unexpect, error);
}

::score::Result<handler::Handler::Sptr> ScoreHandlerFactory::CreateCertVerificationHandler()
{
    ::score::result::Error error(
        static_cast<::score::result::ErrorCode>(::score::crypto::CryptoErrorCode::kUnsupportedOperation),
        ::score::crypto::kCryptoErrorDomain,
        "Certificate verification handler not supported by this score provider");
    return ::score::Result<handler::Handler::Sptr>(::score::unexpect, error);
}

::score::Result<handler::Handler::Sptr> ScoreHandlerFactory::CreateCsrGenerationHandler()
{
    ::score::result::Error error(
        static_cast<::score::result::ErrorCode>(::score::crypto::CryptoErrorCode::kUnsupportedOperation),
        ::score::crypto::kCryptoErrorDomain,
        "CSR generation handler not supported by this score provider");
    return ::score::Result<handler::Handler::Sptr>(::score::unexpect, error);
}

::score::Result<handler::Handler::Sptr> ScoreHandlerFactory::CreateTrustStoreManagementHandler()
{
    ::score::result::Error error(
        static_cast<::score::result::ErrorCode>(::score::crypto::CryptoErrorCode::kUnsupportedOperation),
        ::score::crypto::kCryptoErrorDomain,
        "Trust-store management handler not supported by this score provider");
    return ::score::Result<handler::Handler::Sptr>(::score::unexpect, error);
}

}  // namespace score::crypto::daemon::provider::score_provider::operations::factory

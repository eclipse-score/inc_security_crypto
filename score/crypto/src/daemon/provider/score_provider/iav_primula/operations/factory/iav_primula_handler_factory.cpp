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

#include "score/crypto/src/daemon/provider/score_provider/iav_primula/operations/factory/iav_primula_handler_factory.hpp"
#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/daemon/common/algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/score_provider/iav_primula/operations/kem/iav_primula_kem_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/iav_primula/operations/sign/iav_primula_sign_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/iav_primula/operations/verify/iav_primula_verify_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/kem/kem_executor.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/sign/sign_executor.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/verify/verify_executor.hpp"

#include <memory>
#include <utility>

namespace score::crypto::daemon::provider::score_provider::iav_primula
{

namespace
{
/// @brief Create a score error result for an unsupported algorithm.
///
/// The returned result contains no handler and uses the
/// kUnsupportedAlgorithm error code.
::score::Result<handler::Handler::Sptr> MakeUnsupportedAlgorithmError(const std::string& message)
{
    const ::score::result::Error error(
        static_cast<::score::result::ErrorCode>(::score::crypto::CryptoErrorCode::kUnsupportedAlgorithm),
        ::score::crypto::kCryptoErrorDomain,
        message);
    return ::score::Result<handler::Handler::Sptr>(::score::unexpect, error);
}
}  // namespace

IavPrimulaHandlerFactory::IavPrimulaHandlerFactory(std::shared_ptr<key_management::IKeyFactory> key_factory,
                                                   std::shared_ptr<key_management::IKeySlotHandler> slot_handler,
                                                   key_management::KeyManagementService::Sptr km_service)
    : ScoreHandlerFactory(std::move(key_factory), std::move(slot_handler), std::move(km_service))
{
}

::score::Result<handler::Handler::Sptr> IavPrimulaHandlerFactory::CreateSignHandler(
    const common::AlgorithmId& algorithm)
{
    if (!common::IsPqcSignatureAlgorithm(algorithm))
    {
        return MakeUnsupportedAlgorithmError("Algorithm is not a supported iavPrimula signature algorithm: " +
                                             algorithm);
    }

    return std::make_shared<IavPrimulaSignHandler>(std::make_unique<operations::sign::SignExecutor>(), algorithm);
}

::score::Result<handler::Handler::Sptr> IavPrimulaHandlerFactory::CreateVerifyHandler(
    const common::AlgorithmId& algorithm)
{
    if (!common::IsPqcSignatureAlgorithm(algorithm))
    {
        return MakeUnsupportedAlgorithmError("Algorithm is not a supported iavPrimula verification algorithm: " +
                                             algorithm);
    }

    return std::make_shared<IavPrimulaVerifyHandler>(std::make_unique<operations::verify::VerifyExecutor>(), algorithm);
}

::score::Result<handler::Handler::Sptr> IavPrimulaHandlerFactory::CreateKemHandler(const common::AlgorithmId& algorithm)
{
    if (!common::IsPqcKemAlgorithm(algorithm))
    {
        return MakeUnsupportedAlgorithmError("Algorithm is not a supported iavPrimula KEM algorithm: " + algorithm);
    }

    return std::make_shared<IavPrimulaKemHandler>(std::make_unique<operations::kem::KemExecutor>(), algorithm);
}

}  // namespace score::crypto::daemon::provider::score_provider::iav_primula

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

#ifndef ICRYPTO_HANDLER_FACTORY_HPP
#define ICRYPTO_HANDLER_FACTORY_HPP
#include "i_handler.hpp"
#include "score/crypto/daemon/common/types.hpp"
#include "score/result/result.h"
#include <memory>
#include <string>

namespace score::crypto
{
namespace daemon
{
namespace provider
{
namespace handler
{

/**
 * @brief Abstract interface for cryptographic handler creation.
 */
class ICryptoHandlerFactory
{
  public:
    using Sptr = std::shared_ptr<ICryptoHandlerFactory>;

    virtual ~ICryptoHandlerFactory() = default;

    /**
     * @brief Create a handler for the given handler type and algorithm.
     *
     * @param handlerId  Handler type (e.g. "HASH", "MAC", "KEY_MANAGEMENT").
     * @param algorithm  Requested algorithm (e.g. "SHA256", "HMAC-SHA256").
     * @return The created Handler on success, or an error if the type or
     *         algorithm is not supported.
     */
    virtual ::score::Result<Handler::Sptr> CreateHandler(const common::HandlerId& handlerId,
                                                         const common::AlgorithmId& algorithm) = 0;
};

}  // namespace handler
}  // namespace provider
}  // namespace daemon
}  // namespace score::crypto

#endif  // ICRYPTO_HANDLER_FACTORY_HPP

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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_HANDLER_I_CRYPTO_HANDLER_FACTORY_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_HANDLER_I_CRYPTO_HANDLER_FACTORY_HPP
#include "i_handler.hpp"
#include "score/crypto/src/api/types/algorithm.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/result/result.h"
#include <memory>

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

    ICryptoHandlerFactory(const ICryptoHandlerFactory&) = delete;
    ICryptoHandlerFactory& operator=(const ICryptoHandlerFactory&) = delete;
    ICryptoHandlerFactory(ICryptoHandlerFactory&&) = delete;
    ICryptoHandlerFactory& operator=(ICryptoHandlerFactory&&) = delete;

    /**
     * @brief Create a handler for the given handler type and algorithm.
     *
     * The daemon resolves the client's algorithm name to its catalog row
     * before it asks a provider; a name the catalog does not know never
     * reaches a provider.
     *
     * @param handlerId  Handler type (e.g. "HASH", "MAC", "SIGN").
     * @param algorithm  Catalog row of the requested algorithm.
     * @return The created Handler on success, or an error if the type or
     *         algorithm is not supported.
     */
    virtual ::score::Result<Handler::Sptr> CreateHandler(const common::HandlerId& handlerId,
                                                         const ::score::crypto::AlgorithmDescriptor& algorithm) = 0;

    /**
     * @brief Create the provider's key management handler.
     *
     * A KEY_MANAGEMENT context names no algorithm; each key request carries
     * its own, resolved where the request is decoded.
     *
     * @return The created Handler on success, or an error if the provider has
     *         no key management.
     */
    virtual ::score::Result<Handler::Sptr> CreateKeyManagementHandler() = 0;

    /**
     * @brief Tell whether CreateHandler() would accept this handler type and algorithm.
     *
     * Answers from the same gates CreateHandler() applies, without creating a
     * handler or touching provider resources. Used for capability queries.
     *
     * @return false by default, for factories that do not report capabilities.
     */
    [[nodiscard]] virtual bool IsAlgorithmSupported(const common::HandlerId& /*handlerId*/,
                                                    const ::score::crypto::AlgorithmDescriptor& /*algorithm*/) const
    {
        return false;
    }

  protected:
    ICryptoHandlerFactory() = default;
};

}  // namespace handler
}  // namespace provider
}  // namespace daemon
}  // namespace score::crypto

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_HANDLER_I_CRYPTO_HANDLER_FACTORY_HPP

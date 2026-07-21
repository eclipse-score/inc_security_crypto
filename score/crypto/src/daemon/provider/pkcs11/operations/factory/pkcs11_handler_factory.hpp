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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_OPERATIONS_FACTORY_HANDLER_FACTORY_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_OPERATIONS_FACTORY_HANDLER_FACTORY_HPP

#include "score/crypto/daemon/common/types.hpp"
#include "score/crypto/daemon/key_management/core/key_management_service.hpp"
#include "score/crypto/daemon/provider/handler/i_crypto_handler_factory.hpp"
#include "score/crypto/daemon/provider/handler/i_handler.hpp"
#include "score/crypto/daemon/provider/pkcs11/pkcs11_module.hpp"
#include "score/result/result.h"

#include <memory>

namespace score::crypto::daemon::provider::pkcs11
{

// Forward declaration to avoid circular dependency:
// pkcs11_provider.hpp includes pkcs11_handler_factory.hpp, so we cannot
// include pkcs11_provider.hpp here.  The full definition is available in the .cpp.
class Pkcs11Provider;

/// @brief Predefined handler IDs supported by the PKCS#11 factory.
inline constexpr const char* const kHashHandlerId = "HASH";
inline constexpr const char* const kMacHandlerId = "MAC";
inline constexpr const char* const kKeyManagementHandlerId = "KEY_MANAGEMENT";

/// @brief Factory that creates PKCS#11-backed crypto handlers.
///
/// Each factory instance is associated with a single PKCS#11 module and a
/// reference to the parent Pkcs11Provider. Handlers acquire their own session
/// from the provider pool at construction and return it on destruction.
class Pkcs11HandlerFactory final : public handler::ICryptoHandlerFactory
{
  public:
    /// @param module      Reference to the initialised Pkcs11Module (non-owning).
    /// @param provider    Reference to the owning Pkcs11Provider for session acquisition (non-owning).
    ///                    The provider is also used to obtain KeyManagementService at handler creation time.
    Pkcs11HandlerFactory(const Pkcs11Module& module, Pkcs11Provider& provider) noexcept;
    ~Pkcs11HandlerFactory() override = default;

    Pkcs11HandlerFactory(const Pkcs11HandlerFactory&) = delete;
    Pkcs11HandlerFactory& operator=(const Pkcs11HandlerFactory&) = delete;
    Pkcs11HandlerFactory(Pkcs11HandlerFactory&&) = delete;
    Pkcs11HandlerFactory& operator=(Pkcs11HandlerFactory&&) = delete;

    /// @brief Create a handler for the requested handler/algorithm combination.
    ///
    /// Acquires a session from the provider pool using the handler type's
    /// static kRequirements. The session is released on handler destruction.
    [[nodiscard]] score::Result<handler::Handler::Sptr> CreateHandler(const common::HandlerId& handlerId,
                                                                      const common::AlgorithmId& algorithm) override;

  private:
    [[nodiscard]] score::Result<handler::Handler::Sptr> CreateHashHandler(const common::AlgorithmId& algorithm);
    [[nodiscard]] score::Result<handler::Handler::Sptr> CreateMacHandler(const common::AlgorithmId& algorithm);
    [[nodiscard]] score::Result<handler::Handler::Sptr> CreateKeyManagementHandler();

    const Pkcs11Module& m_module;
    Pkcs11Provider& m_provider;  ///< non-owning; provider always outlives the factory
};

}  // namespace score::crypto::daemon::provider::pkcs11

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_OPERATIONS_FACTORY_HANDLER_FACTORY_HPP

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

#ifndef SCORE_CRYPTO_SRC_DAEMON_MEDIATOR_MEDIATOR_FACTORY_HPP
#define SCORE_CRYPTO_SRC_DAEMON_MEDIATOR_MEDIATOR_FACTORY_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/context/i_mediator_registrar.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/data_manager/i_data_manager.hpp"
#include "score/crypto/src/daemon/key_management/core/key_management_service.hpp"
#include "score/crypto/src/daemon/mediator/i_mediator.hpp"
#include "score/crypto/src/daemon/provider/provider_manager.hpp"

#include <memory>
#include <vector>

namespace score::crypto::daemon::mediator
{

/// @brief Creates the daemon's mediator from the subsystem collaborators.
///
/// Creation builds the mediator registries and asks each registrar to add its subsystem's entries.
/// The registries are handed to the mediator and are not changed after creation. The mediator
/// package names no subsystem: a subsystem takes part by implementing `IMediatorRegistrar`.
class MediatorFactory final
{
  public:
    /// @brief Create the mediator and populate its registries.
    /// @param data_manager Data manager shared by the mediator.
    /// @param provider_manager Provider manager that owns the providers.
    /// @param km_service Key management service used for key affinity and key binding, or null when
    ///        key management is not configured.
    /// @param registrars Subsystems that add entries to the registries. None may be null.
    /// @return The mediator, or an error if a registrar is null, a registration is rejected, or a
    ///         mediator query is registered for an operation the mediator implements itself.
    [[nodiscard]] static score::crypto::Expected<std::shared_ptr<IMediator>, common::DaemonErrorCode> Create(
        data_manager::IDataManager::Sptr data_manager,
        provider::ProviderManager::Sptr provider_manager,
        key_management::KeyManagementService::Sptr km_service,
        const std::vector<common::IMediatorRegistrar::Sptr>& registrars);
};

}  // namespace score::crypto::daemon::mediator

#endif  // SCORE_CRYPTO_SRC_DAEMON_MEDIATOR_MEDIATOR_FACTORY_HPP

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

#ifndef SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_SLOT_DEPLOYMENT_I_DEPLOYMENT_WRITER_HPP
#define SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_SLOT_DEPLOYMENT_I_DEPLOYMENT_WRITER_HPP

#include "score/crypto/common/types.hpp"
#include "score/crypto/daemon/common/daemon_error.hpp"
#include "score/crypto/daemon/key_management/interfaces/key_slot_config.hpp"

#include <string>
#include <variant>

namespace score::crypto::daemon::key_management
{

/// @brief Interface for format-specific deployment descriptor writers.
///
/// Mirrors IDeploymentLoader: one concrete class per serialization format.
/// The path safety pre-check is performed by DeploymentWriterFactory *before*
/// calling Write(), so implementations can assume a valid path.
///
/// ### Adding a new format
/// 1. Implement this interface in a new class (e.g., `JsonDeploymentWriter`).
/// 2. Place the class under `slot/deployment/<format>/`.
/// 3. Register it in `DeploymentWriterFactory::Create()`.
class IDeploymentWriter
{
  public:
    virtual ~IDeploymentWriter() = default;

    /// @brief Write a SlotDeploymentInfo to the given (pre-validated) path.
    ///
    /// @param path  Absolute path to the deployment descriptor file. The caller
    ///              (factory) has already verified it is safe.
    /// @param info  The deployment info to persist.
    /// @return std::monostate on success, or DaemonErrorCode on failure.
    [[nodiscard]] virtual score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Write(
        const std::string& path,
        const SlotDeploymentInfo& info) = 0;
};

}  // namespace score::crypto::daemon::key_management

#endif  // SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_SLOT_DEPLOYMENT_I_DEPLOYMENT_WRITER_HPP

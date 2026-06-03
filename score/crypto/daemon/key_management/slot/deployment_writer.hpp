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

#ifndef SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_DEPLOYMENT_WRITER_HPP
#define SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_DEPLOYMENT_WRITER_HPP

#include "score/crypto/common/types.hpp"
#include "score/crypto/daemon/common/daemon_error.hpp"
#include "score/crypto/daemon/key_management/interfaces/key_slot_config.hpp"

#include <string>
#include <string_view>
#include <variant>

namespace score::crypto::daemon::key_management
{

/// @brief Writes dynamic slot and key information to a deployment descriptor.
///
/// Used during key update operations (generate-to-slot, import-to-slot) to
/// persist new key properties back to the deployment path.
///
/// ### Atomicity (future extension)
///
/// The current implementation writes directly to the target path. A future
/// extension may implement atomic write (write to temp file, then rename)
/// to avoid partial writes on crash.
///
/// ### Thread safety
///
/// Concurrent writes to the same deployment path require external
/// synchronisation (e.g., a per-slot mutex in the registry).
class DeploymentWriter
{
  public:
    /// @brief Write a SlotDeploymentInfo to the given path in the specified format.
    ///
    /// @param path    Absolute path to the deployment descriptor file.
    /// @param format  Format hint: "kv", "json", "bin".
    /// @param info    The deployment info to write.
    /// @return std::monostate on success, or DaemonErrorCode on failure.
    [[nodiscard]] static score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    Write(const std::string& path, const std::string& format, const SlotDeploymentInfo& info);

  private:
    static constexpr std::string_view LOG_PREFIX = "[DEPLOYMENT_WRITER]";
};

}  // namespace score::crypto::daemon::key_management

#endif  // SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_DEPLOYMENT_WRITER_HPP

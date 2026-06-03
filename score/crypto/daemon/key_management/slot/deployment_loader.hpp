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

#ifndef SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_DEPLOYMENT_LOADER_HPP
#define SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_DEPLOYMENT_LOADER_HPP

#include "score/crypto/common/types.hpp"
#include "score/crypto/daemon/common/daemon_error.hpp"
#include "score/crypto/daemon/key_management/interfaces/key_slot_config.hpp"

#include <string>
#include <string_view>

namespace score::crypto::daemon::key_management
{

/// @brief Loads dynamic slot and key information from a deployment descriptor.
///
/// The deployment descriptor is an external file (or folder) referenced by
/// `KeySlotConfig::deployment_path`. Its content is format-dependent
/// (`KeySlotConfig::deployment_format`):
///
///   - `"kv"` (default): Simple key=value text file. Lines of the form
///     `key=value`, blank lines ignored, `#` comments supported.
///     Sections `[metadata]` and `[key]` separate the two maps.
///
///   - `"json"`: Reserved for future use (requires JSON library dependency).
///
///   - `"bin"`:  Reserved for future use (binary/flatbuffer encoding).
///
/// ### Security
///
/// - The file path must be absolute (no relative components).
/// - Path traversal (`..`) is rejected.
/// - The loader does not follow symlinks (defence-in-depth; OS-level
///   enforcement may vary).
///
/// ### Thread safety
///
/// `Load()` is stateless and may be called concurrently from multiple threads
/// for different deployment paths. Concurrent reads of the same path are safe;
/// concurrent read + write requires external synchronisation (see DeploymentWriter).
class DeploymentLoader
{
  public:
    /// @brief Load a deployment descriptor from the given path and format.
    ///
    /// @param path    Absolute path to the deployment descriptor file.
    /// @param format  Format hint: "kv", "json", "bin".
    /// @return Parsed SlotDeploymentInfo on success, or DaemonErrorCode on failure.
    [[nodiscard]] static score::crypto::Expected<SlotDeploymentInfo, score::crypto::daemon::common::DaemonErrorCode>
    Load(const std::string& path, const std::string& format);

  private:
    static constexpr std::string_view LOG_PREFIX = "[DEPLOYMENT_LOADER]";
};

}  // namespace score::crypto::daemon::key_management

#endif  // SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_DEPLOYMENT_LOADER_HPP

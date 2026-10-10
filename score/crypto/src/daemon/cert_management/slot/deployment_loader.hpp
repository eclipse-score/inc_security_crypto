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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_SLOT_DEPLOYMENT_LOADER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_SLOT_DEPLOYMENT_LOADER_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/storage/deployment_descriptor.hpp"

#include <string>
#include <string_view>

namespace score::crypto::daemon::cert_management
{

/// @brief Loads a certificate slot or trust store deployment descriptor.
///
/// The descriptor uses the section-based KV format from daemon/common/storage/.
/// Certificate and CRL sections are defined by cert_section_names /
/// cert_deployment_keys in cert_types.hpp.
///
/// Thread safety: Load() is stateless and may be called concurrently.
class DeploymentLoader
{
  public:
    /// @brief Load a deployment descriptor from the given path and format.
    ///
    /// @param path    Absolute path to the descriptor file.
    /// @param format  Format hint: "kv" (default); future: "json", "bin".
    /// @return Parsed DeploymentDescriptor on success, or DaemonErrorCode on failure.
    [[nodiscard]] static score::crypto::Expected<score::crypto::daemon::common::storage::DeploymentDescriptor,
                                                 score::crypto::daemon::common::DaemonErrorCode>
    Load(const std::string& path, const std::string& format);

  private:
    static constexpr std::string_view kLogPrefix = "[CERT_DEPLOYMENT_LOADER] ";
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_SLOT_DEPLOYMENT_LOADER_HPP

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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_SLOT_DEPLOYMENT_WRITER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_SLOT_DEPLOYMENT_WRITER_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/storage/deployment_descriptor.hpp"

#include <string>
#include <string_view>
#include <variant>

namespace score::crypto::daemon::cert_management
{

/// @brief Writes a certificate slot or trust store deployment descriptor.
///
/// Concurrent writes to the same deployment path require external synchronisation.
class DeploymentWriter
{
  public:
    /// @brief Write a DeploymentDescriptor to the given path in the specified format.
    ///
    /// @param path        Absolute path to the descriptor file.
    /// @param format      Format hint: "kv"; future: "json", "bin".
    /// @param descriptor  The descriptor to write.
    /// @return std::monostate on success, or DaemonErrorCode on failure.
    [[nodiscard]] static score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Write(
        const std::string& path,
        const std::string& format,
        const score::crypto::daemon::common::storage::DeploymentDescriptor& descriptor);

  private:
    static constexpr std::string_view kLogPrefix = "[CERT_DEPLOYMENT_WRITER] ";
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_SLOT_DEPLOYMENT_WRITER_HPP

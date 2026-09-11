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

#ifndef SCORE_CRYPTO_SRC_DAEMON_COMMON_STORAGE_I_DEPLOYMENT_WRITER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_COMMON_STORAGE_I_DEPLOYMENT_WRITER_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/storage/deployment_descriptor.hpp"

#include <string>
#include <variant>

namespace score::crypto::daemon::common::storage
{

/// @brief Interface for format-specific deployment descriptor writers.
class IDeploymentWriter
{
  public:
    virtual ~IDeploymentWriter() = default;

    /// @brief Write a DeploymentDescriptor to the given (pre-validated) path.
    [[nodiscard]] virtual score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Write(
        const std::string& path,
        const DeploymentDescriptor& descriptor) = 0;
};

}  // namespace score::crypto::daemon::common::storage

#endif  // SCORE_CRYPTO_SRC_DAEMON_COMMON_STORAGE_I_DEPLOYMENT_WRITER_HPP

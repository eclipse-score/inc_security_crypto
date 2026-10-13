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

#ifndef SCORE_CRYPTO_SRC_DAEMON_COMMON_STORAGE_I_DEPLOYMENT_LOADER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_COMMON_STORAGE_I_DEPLOYMENT_LOADER_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/storage/deployment_descriptor.hpp"

#include <string>

namespace score::crypto::daemon::common::storage
{

/// @brief Interface for format-specific deployment descriptor loaders.
///
/// Each concrete implementation handles exactly one serialization format.
/// Path safety pre-checks are performed by the factory before calling Load().
class IDeploymentLoader
{
  public:
    virtual ~IDeploymentLoader() = default;

    /// @brief Load a DeploymentDescriptor from the given (pre-validated) path.
    [[nodiscard]] virtual score::crypto::Expected<DeploymentDescriptor, score::crypto::daemon::common::DaemonErrorCode>
    Load(const std::string& path) = 0;
};

}  // namespace score::crypto::daemon::common::storage

#endif  // SCORE_CRYPTO_SRC_DAEMON_COMMON_STORAGE_I_DEPLOYMENT_LOADER_HPP

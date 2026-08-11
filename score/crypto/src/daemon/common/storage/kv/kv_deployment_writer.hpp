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

#ifndef SCORE_CRYPTO_SRC_DAEMON_COMMON_STORAGE_KV_KV_DEPLOYMENT_WRITER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_COMMON_STORAGE_KV_KV_DEPLOYMENT_WRITER_HPP

#include "score/crypto/src/daemon/common/storage/i_deployment_writer.hpp"

#include <string_view>

namespace score::crypto::daemon::common::storage
{

/// @brief Writes a DeploymentDescriptor to a key=value text file.
///
/// Produces the same section/key=value format that KvDeploymentLoader can read back.
/// Writes atomically via a temporary sibling file and rename — the existing file
/// is preserved until the new content is fully flushed.
class KvDeploymentWriter final : public IDeploymentWriter
{
  public:
    [[nodiscard]] score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Write(
        const std::string& path,
        const DeploymentDescriptor& descriptor) override;

};

}  // namespace score::crypto::daemon::common::storage

#endif  // SCORE_CRYPTO_SRC_DAEMON_COMMON_STORAGE_KV_KV_DEPLOYMENT_WRITER_HPP

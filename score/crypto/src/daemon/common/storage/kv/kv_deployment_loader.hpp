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

#ifndef SCORE_CRYPTO_SRC_DAEMON_COMMON_STORAGE_KV_KV_DEPLOYMENT_LOADER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_COMMON_STORAGE_KV_KV_DEPLOYMENT_LOADER_HPP

#include "score/crypto/src/daemon/common/storage/i_deployment_loader.hpp"

#include <string_view>

namespace score::crypto::daemon::common::storage
{

/// @brief Loads a DeploymentDescriptor from a key=value text file.
///
/// File format:
/// @code
///   # comment
///   [section_name]
///   key = value
///   another_key = another_value
///
///   [another_section]
///   foo = bar
/// @endcode
///
/// - Lines starting with '#' are comments (ignored).
/// - Blank lines are ignored.
/// - Section headers switch the active section.
/// - Lines without '=' are silently skipped.
/// - Keys and values are whitespace-trimmed.
class KvDeploymentLoader final : public IDeploymentLoader
{
  public:
    [[nodiscard]] score::crypto::Expected<DeploymentDescriptor, score::crypto::daemon::common::DaemonErrorCode> Load(
        const std::string& path) override;

  private:
    static constexpr std::string_view kLogPrefix = "[KV_DEPLOYMENT_LOADER_COMMON] ";
};

}  // namespace score::crypto::daemon::common::storage

#endif  // SCORE_CRYPTO_SRC_DAEMON_COMMON_STORAGE_KV_KV_DEPLOYMENT_LOADER_HPP

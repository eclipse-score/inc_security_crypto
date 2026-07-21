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

#ifndef SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_SLOT_DEPLOYMENT_KV_KV_DEPLOYMENT_LOADER_HPP
#define SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_SLOT_DEPLOYMENT_KV_KV_DEPLOYMENT_LOADER_HPP

#include "score/crypto/daemon/key_management/slot/deployment/i_deployment_loader.hpp"

#include <string_view>

namespace score::crypto::daemon::key_management
{

/// @brief Loads a SlotDeploymentInfo from a key=value text file.
///
/// File format:
/// @code
///   # comment
///   [metadata]
///   availability = active
///   provisioned_at = 2025-11-03T08:42:00Z
///
///   [key]
///   key_path = /etc/crypto/keys/hmac.bin
///   key_format = raw
/// @endcode
///
/// - Lines starting with `#` are comments and are ignored.
/// - Blank lines are ignored.
/// - Section headers `[metadata]` and `[key]` switch the active map.
/// - Lines without a `=` separator are silently skipped.
/// - Keys and values are whitespace-trimmed.
class KvDeploymentLoader : public IDeploymentLoader
{
  public:
    [[nodiscard]] score::crypto::Expected<SlotDeploymentInfo, score::crypto::daemon::common::DaemonErrorCode> Load(
        const std::string& path) override;

  private:
    static constexpr std::string_view kLogPrefix = "[KV_DEPLOYMENT_LOADER] ";
};

}  // namespace score::crypto::daemon::key_management

#endif  // SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_SLOT_DEPLOYMENT_KV_KV_DEPLOYMENT_LOADER_HPP

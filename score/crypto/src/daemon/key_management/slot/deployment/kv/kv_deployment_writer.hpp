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

#ifndef SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_SLOT_DEPLOYMENT_KV_KV_DEPLOYMENT_WRITER_HPP
#define SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_SLOT_DEPLOYMENT_KV_KV_DEPLOYMENT_WRITER_HPP

#include "score/crypto/daemon/key_management/slot/deployment/i_deployment_writer.hpp"

#include <string_view>

namespace score::crypto::daemon::key_management
{

/// @brief Writes a SlotDeploymentInfo to a key=value text file.
///
/// Produces the same `[metadata]` / `[key]` section format that
/// KvDeploymentLoader can read back. Existing file content is replaced
/// (opened with `std::ios::trunc`).
///
/// @note Writes are not currently atomic. A future extension may implement
///       write-then-rename to protect against partial writes on crash.
class KvDeploymentWriter : public IDeploymentWriter
{
  public:
    [[nodiscard]] score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Write(
        const std::string& path,
        const SlotDeploymentInfo& info) override;

  private:
    static constexpr std::string_view kLogPrefix = "[KV_DEPLOYMENT_WRITER] ";
};

}  // namespace score::crypto::daemon::key_management

#endif  // SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_SLOT_DEPLOYMENT_KV_KV_DEPLOYMENT_WRITER_HPP

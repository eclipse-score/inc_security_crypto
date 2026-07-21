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

#include "score/crypto/daemon/key_management/slot/deployment/kv/kv_deployment_writer.hpp"

#include "score/mw/log/logging.h"
#include <fstream>

#include <string>

namespace score::crypto::daemon::key_management
{

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> KvDeploymentWriter::Write(
    const std::string& path,
    const SlotDeploymentInfo& info)
{
    std::ofstream file(path, std::ios::trunc);
    if (!file.is_open())
    {
        score::mw::log::LogError() << kLogPrefix << "Cannot open deployment descriptor for writing:" << path;
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    file << "[metadata]\n";
    for (const auto& [key, value] : info.metadata)
    {
        file << key << '=' << value << '\n';
    }

    file << "\n[key]\n";
    for (const auto& [key, value] : info.key_properties)
    {
        file << key << '=' << value << '\n';
    }

    if (!file.good())
    {
        score::mw::log::LogError() << kLogPrefix << "Write error for deployment descriptor:" << path;
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }

    return std::monostate{};
}

}  // namespace score::crypto::daemon::key_management

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

#include "score/crypto/src/daemon/common/storage/kv/kv_deployment_writer.hpp"

#include "score/mw/log/logging.h"

#include <fstream>

namespace score::crypto::daemon::common::storage
{

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> KvDeploymentWriter::Write(
    const std::string& path,
    const DeploymentDescriptor& descriptor)
{
    std::ofstream file(path, std::ios::trunc);
    if (!file.is_open())
    {
        score::mw::log::LogError() << kLogPrefix << "Cannot open for writing: " << path;
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }

    for (const auto& [section, entries] : descriptor.sections)
    {
        file << '[' << section << ']' << '\n';
        for (const auto& [key, value] : entries)
        {
            file << key << " = " << value << '\n';
        }
        file << '\n';
    }

    if (!file.good())
    {
        score::mw::log::LogError() << kLogPrefix << "Write failed for: " << path;
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }
    return std::monostate{};
}

}  // namespace score::crypto::daemon::common::storage

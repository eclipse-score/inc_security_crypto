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

#include "score/crypto/daemon/key_management/slot/deployment_writer.hpp"

#include "score/crypto/daemon/key_management/slot/deployment/deployment_path_utils.hpp"
#include "score/crypto/daemon/key_management/slot/deployment/kv/kv_deployment_writer.hpp"

#include "score/mw/log/logging.h"

#include <string>

namespace score::crypto::daemon::key_management
{

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
DeploymentWriter::Write(const std::string& path, const std::string& format, const SlotDeploymentInfo& info)
{
    if (!IsDeploymentPathSafe(path))
    {
        score::mw::log::LogError() << LOG_PREFIX << "Unsafe deployment path rejected:" << path;
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    if (format == "kv")
    {
        return KvDeploymentWriter{}.Write(path, info);
    }
    // To add a new format: include its header above and add a branch here.
    // Example: if (format == "json") { return JsonDeploymentWriter{}.Write(path, info); }

    score::mw::log::LogError() << LOG_PREFIX << "Unsupported deployment format:" << format;
    return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
}

}  // namespace score::crypto::daemon::key_management

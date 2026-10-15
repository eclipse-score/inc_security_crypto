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

#include "score/crypto/src/daemon/cert_management/slot/deployment_writer.hpp"

#include "score/crypto/src/daemon/common/storage/deployment_path_utils.hpp"
#include "score/crypto/src/daemon/common/storage/kv/kv_deployment_writer.hpp"

#include "score/mw/log/logging.h"

namespace score::crypto::daemon::cert_management
{

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> DeploymentWriter::Write(
    const std::string& path,
    const std::string& format,
    const score::crypto::daemon::common::storage::DeploymentDescriptor& descriptor)
{
    if (!score::crypto::daemon::common::storage::IsDeploymentPathSafe(path))
    {
        score::mw::log::LogError() << kLogPrefix << "Unsafe deployment path rejected: " << path;
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    if (format == "kv")
    {
        return score::crypto::daemon::common::storage::KvDeploymentWriter{}.Write(path, descriptor);
    }

    score::mw::log::LogError() << kLogPrefix << "Unsupported deployment format: " << format;
    return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
}

}  // namespace score::crypto::daemon::cert_management

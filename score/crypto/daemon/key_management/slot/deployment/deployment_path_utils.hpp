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

#ifndef SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_SLOT_DEPLOYMENT_DEPLOYMENT_PATH_UTILS_HPP
#define SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_SLOT_DEPLOYMENT_DEPLOYMENT_PATH_UTILS_HPP

#include <string>

namespace score::crypto::daemon::key_management
{

/// @brief Returns true if the path is absolute and contains no ".." path traversal components.
///
/// Used as a single shared security pre-check by DeploymentLoaderFactory and
/// DeploymentWriterFactory before dispatching to a format-specific implementation.
/// Centralises path validation so it is not duplicated across every format class.
[[nodiscard]] inline bool IsDeploymentPathSafe(const std::string& path) noexcept
{
    if (path.empty())
    {
        return false;
    }

    // Require absolute path (Unix: starts with '/').
    const bool is_absolute = (path[0] == '/') || (path.size() >= 3U && path[1] == ':');
    if (!is_absolute)
    {
        return false;
    }

    // Reject path traversal: ".." as a standalone component.
    if (path.find("..") != std::string::npos)
    {
        return false;
    }

    return true;
}

}  // namespace score::crypto::daemon::key_management

#endif  // SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_SLOT_DEPLOYMENT_DEPLOYMENT_PATH_UTILS_HPP

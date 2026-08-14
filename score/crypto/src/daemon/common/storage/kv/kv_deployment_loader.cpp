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

#include "score/crypto/src/daemon/common/storage/kv/kv_deployment_loader.hpp"

#include "score/crypto/src/daemon/common/storage/file_io.hpp"
#include "score/mw/log/logging.h"

#include <sstream>
#include <string>

namespace score::crypto::daemon::common::storage
{

namespace
{

[[nodiscard]] std::string Trim(std::string_view sv) noexcept
{
    const auto start = sv.find_first_not_of(" \t\r\n");
    if (start == std::string_view::npos)
    {
        return {};
    }
    const auto end = sv.find_last_not_of(" \t\r\n");
    return std::string{sv.substr(start, end - start + 1U)};
}

}  // namespace

score::crypto::Expected<DeploymentDescriptor, score::crypto::daemon::common::DaemonErrorCode> KvDeploymentLoader::Load(
    const std::string& path)
{
    constexpr std::size_t kMaxDescriptorSize = 64U * 1024U;
    auto read_result = ReadFile(path, kMaxDescriptorSize);
    if (!read_result.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "Cannot open: " << path;
        return score::crypto::make_unexpected(read_result.error());
    }

    const auto& bytes = read_result.value();
    std::istringstream stream{std::string{reinterpret_cast<const char*>(bytes.data()), bytes.size()}};

    DeploymentDescriptor descriptor;
    std::string current_section;
    std::string line;

    while (std::getline(stream, line))
    {
        const std::string trimmed = Trim(line);
        if (trimmed.empty() || trimmed[0] == '#')
        {
            continue;
        }
        if (trimmed.front() == '[' && trimmed.back() == ']')
        {
            current_section = Trim(trimmed.substr(1U, trimmed.size() - 2U));
            continue;
        }
        if (current_section.empty())
        {
            continue;
        }
        const auto eq_pos = trimmed.find('=');
        if (eq_pos == std::string::npos)
        {
            continue;
        }
        const std::string key = Trim(trimmed.substr(0U, eq_pos));
        const std::string value = Trim(trimmed.substr(eq_pos + 1U));
        descriptor.sections[current_section][key] = value;
    }

    return descriptor;
}

}  // namespace score::crypto::daemon::common::storage

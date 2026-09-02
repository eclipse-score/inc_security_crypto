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

#include "score/crypto/src/daemon/common/storage/file_io.hpp"

#include <sstream>

namespace score::crypto::daemon::common::storage
{

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> KvDeploymentWriter::Write(
    const std::string& path,
    const DeploymentDescriptor& descriptor)
{
    std::ostringstream oss;
    for (const auto& [section, entries] : descriptor.sections)
    {
        oss << '[' << section << ']' << '\n';
        for (const auto& [key, value] : entries)
        {
            oss << key << " = " << value << '\n';
        }
        oss << '\n';
    }

    std::string content = oss.str();
    if (content.empty())
        content = "# empty deployment descriptor\n";
    const auto bytes =
        score::crypto::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t*>(content.data()), content.size()};
    return WriteFile(path, bytes);
}

}  // namespace score::crypto::daemon::common::storage

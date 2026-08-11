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
/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/
#include "score/crypto/src/daemon/common/storage/file_io.hpp"

#include <filesystem>
#include <fstream>

namespace score::crypto::daemon::common::storage
{

score::crypto::Expected<std::vector<std::uint8_t>, DaemonErrorCode> ReadFile(const std::string& path,
                                                                             std::size_t max_size)
{
    std::ifstream input(path, std::ios::binary);
    if (!input)
        return score::crypto::make_unexpected(DaemonErrorCode::kResourceNotAllocated);
    input.seekg(0, std::ios::end);
    const auto size = input.tellg();
    if (size <= 0 || static_cast<std::uintmax_t>(size) > max_size)
        return score::crypto::make_unexpected(DaemonErrorCode::kInvalidArgument);
    input.seekg(0, std::ios::beg);
    std::vector<std::uint8_t> data(static_cast<std::size_t>(size));
    input.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!input)
        return score::crypto::make_unexpected(DaemonErrorCode::kInternalError);
    return data;
}

score::crypto::Expected<std::monostate, DaemonErrorCode> WriteFile(const std::string& path,
                                                                   score::crypto::span<const std::uint8_t> data)
{
    if (path.empty() || data.empty())
        return score::crypto::make_unexpected(DaemonErrorCode::kInvalidArgument);
    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(path).parent_path(), ec);
    if (ec)
        return score::crypto::make_unexpected(DaemonErrorCode::kInternalError);
    const std::string temporary = path + ".tmp";
    {
        std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
        if (!output)
            return score::crypto::make_unexpected(DaemonErrorCode::kPersistFailed);
        output.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        output.flush();
        if (!output)
            return score::crypto::make_unexpected(DaemonErrorCode::kPersistFailed);
    }
    std::filesystem::rename(temporary, path, ec);
    if (ec)
    {
        std::filesystem::remove(temporary, ec);
        return score::crypto::make_unexpected(DaemonErrorCode::kPersistFailed);
    }
    return std::monostate{};
}

}  // namespace score::crypto::daemon::common::storage

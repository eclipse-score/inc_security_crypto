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
#include "score/crypto/src/daemon/common/storage/file_io.hpp"

#include "score/filesystem/error.h"
#include "score/filesystem/filestream/file_factory.h"
#include "score/filesystem/filestream/file_stream.h"
#include "score/filesystem/filesystem.h"

namespace score::crypto::daemon::common::storage
{

score::crypto::Expected<std::vector<std::uint8_t>, DaemonErrorCode> ReadFile(const std::string& path,
                                                                             std::size_t max_size)
{
    score::filesystem::FileFactory factory{};
    auto open_result = factory.Open(score::filesystem::Path{path}, std::ios::binary | std::ios::in);
    if (!open_result.has_value())
        return score::crypto::make_unexpected(DaemonErrorCode::kResourceNotAllocated);

    auto& stream = *open_result.value();
    stream.seekg(0, std::ios::end);
    const auto size = stream.tellg();
    if (size <= 0 || static_cast<std::uintmax_t>(size) > max_size)
        return score::crypto::make_unexpected(DaemonErrorCode::kInvalidArgument);
    stream.seekg(0, std::ios::beg);
    std::vector<std::uint8_t> data(static_cast<std::size_t>(size));
    stream.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!stream)
        return score::crypto::make_unexpected(DaemonErrorCode::kInternalError);
    return data;
}

score::crypto::Expected<std::monostate, DaemonErrorCode> WriteFile(const std::string& path,
                                                                   score::crypto::span<const std::uint8_t> data)
{
    if (path.empty() || data.empty())
        return score::crypto::make_unexpected(DaemonErrorCode::kInvalidArgument);

    const score::filesystem::Path target_path{path};
    score::filesystem::StandardFilesystem fs{};
    const auto parent = target_path.ParentPath();
    if (!parent.Empty())
    {
        if (!fs.CreateDirectories(parent).has_value())
            return score::crypto::make_unexpected(DaemonErrorCode::kInternalError);
    }

    score::filesystem::FileFactory factory{};
    auto stream_result = factory.AtomicUpdate(target_path, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!stream_result.has_value())
        return score::crypto::make_unexpected(DaemonErrorCode::kPersistFailed);

    auto& stream = *stream_result.value();
    stream.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    stream.flush();
    if (!stream)
        // Stream is in a bad state; Close() (called by the destructor) will detect this
        // and clean up the temp file rather than renaming it.
        return score::crypto::make_unexpected(DaemonErrorCode::kPersistFailed);

    // Close() triggers the atomic rename — check it explicitly to confirm success.
    // The destructor calls Close() again on the way out; a second call on an already-closed
    // stream returns an error that the destructor ignores, which is safe.
    if (!stream_result.value()->Close().has_value())
        return score::crypto::make_unexpected(DaemonErrorCode::kPersistFailed);
    return std::monostate{};
}

bool FileExists(const std::string& path)
{
    score::filesystem::StandardFilesystem fs{};
    const auto result = fs.IsRegularFile(score::filesystem::Path{path});
    return result.has_value() && result.value();
}

score::crypto::Expected<std::monostate, DaemonErrorCode> RemoveFile(const std::string& path)
{
    if (path.empty())
        return score::crypto::make_unexpected(DaemonErrorCode::kInvalidArgument);
    score::filesystem::StandardFilesystem fs{};
    const auto result = fs.Remove(score::filesystem::Path{path});
    if (!result.has_value() && result.error() != score::filesystem::ErrorCode::kFileOrDirectoryDoesNotExist)
        return score::crypto::make_unexpected(DaemonErrorCode::kPersistFailed);
    return std::monostate{};
}

}  // namespace score::crypto::daemon::common::storage

/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/
#ifndef SCORE_CRYPTO_SRC_DAEMON_COMMON_STORAGE_FILE_IO_HPP
#define SCORE_CRYPTO_SRC_DAEMON_COMMON_STORAGE_FILE_IO_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"

#include <cstdint>
#include <string>
#include <variant>
#include <vector>

namespace score::crypto::daemon::common::storage
{

/// Read the entire binary contents of @p path into a byte vector.
///
/// @param path     Absolute or relative path to the file.
/// @param max_size Maximum accepted file size in bytes. Returns kInvalidArgument
///                 if the file is empty or exceeds this limit.
/// @return Byte vector on success; kResourceNotAllocated if the file cannot be
///         opened, kInvalidArgument if size is out of range, kInternalError on
///         a partial read.
[[nodiscard]] score::crypto::Expected<std::vector<std::uint8_t>, DaemonErrorCode>
ReadFile(const std::string& path, std::size_t max_size);

/// Write @p data to @p path atomically via a temporary file and rename.
///
/// Creates parent directories if they do not exist. Writes to a sibling
/// <path>.tmp first, then renames atomically. The temporary file is removed
/// on rename failure.
///
/// @return std::monostate on success; kInvalidArgument if path or data is
///         empty, kInternalError if the directory cannot be created,
///         kPersistFailed on write or rename failure.
[[nodiscard]] score::crypto::Expected<std::monostate, DaemonErrorCode>
WriteFile(const std::string& path, score::crypto::span<const std::uint8_t> data);

}  // namespace score::crypto::daemon::common::storage

#endif  // SCORE_CRYPTO_SRC_DAEMON_COMMON_STORAGE_FILE_IO_HPP

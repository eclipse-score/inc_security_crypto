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
#include "score/mw/log/logging.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <string>
#include <string_view>

namespace score::crypto::daemon::common::storage
{
namespace
{

/// Closes a POSIX file descriptor when it goes out of scope.
class FdGuard
{
  public:
    explicit FdGuard(int fd) noexcept : m_fd{fd} {}
    ~FdGuard()
    {
        if (m_fd >= 0)
        {
            static_cast<void>(::close(m_fd));
        }
    }

    FdGuard(const FdGuard&) = delete;
    FdGuard& operator=(const FdGuard&) = delete;
    FdGuard(FdGuard&&) = delete;
    FdGuard& operator=(FdGuard&&) = delete;

    [[nodiscard]] int Get() const noexcept
    {
        return m_fd;
    }

    /// Close now and report whether the close succeeded.
    [[nodiscard]] bool Close() noexcept
    {
        const int fd = m_fd;
        m_fd = -1;
        return ::close(fd) == 0;
    }

  private:
    int m_fd;
};

/// Write zeros over the first @p size bytes of the open file @p fd.
bool OverwriteWithZeros(int fd, off_t size) noexcept
{
    constexpr std::size_t kChunkSize = 4096U;
    const std::array<std::uint8_t, kChunkSize> zeros{};

    off_t offset = 0;
    while (offset < size)
    {
        const auto remaining = static_cast<std::size_t>(size - offset);
        const std::size_t chunk = remaining < kChunkSize ? remaining : kChunkSize;
        const ssize_t written = ::pwrite(fd, zeros.data(), chunk, offset);
        if (written < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return false;
        }
        if (written == 0)
        {
            return false;
        }
        offset += static_cast<off_t>(written);
    }
    return true;
}

/// fsync the directory that holds @p path, so a change to its entries is durable.
///
/// A file system that cannot sync a directory (EINVAL) already makes the entry update
/// durable by other means, so that counts as success.
bool SyncParentDirectory(const std::string& path) noexcept
{
    const auto slash = path.find_last_of('/');
    const std::string parent = (slash == std::string::npos) ? std::string{"."}
                               : (slash == 0U)              ? std::string{"/"}
                                                            : path.substr(0U, slash);
    FdGuard dir{::open(parent.c_str(), O_RDONLY | O_CLOEXEC)};
    if (dir.Get() < 0)
    {
        return false;
    }
    if ((::fsync(dir.Get()) != 0) && (errno != EINVAL))
    {
        return false;
    }
    return dir.Close();
}

/// Log a failed step of @p operation together with the errno it left, and return @p code.
score::crypto::Expected<std::monostate, DaemonErrorCode> StepFailed(std::string_view operation,
                                                                    std::string_view step,
                                                                    DaemonErrorCode code)
{
    const int error_number = errno;
    score::mw::log::LogError() << "[FILE_IO] " << operation << ": " << step << " failed (errno " << error_number << ")";
    return score::crypto::make_unexpected(code);
}

}  // namespace

score::crypto::Expected<std::vector<std::uint8_t>, DaemonErrorCode> ReadFile(const std::string& path,
                                                                             std::size_t max_size)
{
    const auto exists = FileExists(path);
    if (!exists.has_value())
    {
        return score::crypto::make_unexpected(exists.error());
    }
    if (!exists.value())
    {
        return score::crypto::make_unexpected(DaemonErrorCode::kResourceNotAllocated);
    }

    score::filesystem::FileFactory factory{};
    auto open_result = factory.Open(score::filesystem::Path{path}, std::ios::binary | std::ios::in);
    if (!open_result.has_value())
    {
        return score::crypto::make_unexpected(open_result.error() ==
                                                      score::filesystem::ErrorCode::kFileOrDirectoryDoesNotExist
                                                  ? DaemonErrorCode::kResourceNotAllocated
                                                  : DaemonErrorCode::kInternalError);
    }

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

score::crypto::Expected<bool, DaemonErrorCode> FileExists(const std::string& path)
{
    if (path.empty())
        return score::crypto::make_unexpected(DaemonErrorCode::kInvalidArgument);

    score::filesystem::StandardFilesystem fs{};
    const auto result = fs.IsRegularFile(score::filesystem::Path{path});
    if (!result.has_value())
    {
        if (result.error() == score::filesystem::ErrorCode::kFileOrDirectoryDoesNotExist)
            return false;
        return score::crypto::make_unexpected(DaemonErrorCode::kInternalError);
    }
    return result.value();
}

score::crypto::Expected<std::monostate, DaemonErrorCode> RemoveFile(const std::string& path)
{
    if (path.empty())
        return score::crypto::make_unexpected(DaemonErrorCode::kInvalidArgument);
    score::filesystem::StandardFilesystem fs{};
    const auto result = fs.Remove(score::filesystem::Path{path});
    if (!result.has_value())
    {
        const auto status = fs.Status(score::filesystem::Path{path});
        if (status.has_value() && status->Type() == score::filesystem::FileType::kNotFound)
            return std::monostate{};
        if (result.error() == score::filesystem::ErrorCode::kFileOrDirectoryDoesNotExist)
            return std::monostate{};
        return score::crypto::make_unexpected(DaemonErrorCode::kPersistFailed);
    }
    return std::monostate{};
}

// SecureEraseFile uses POSIX calls directly: score::filesystem has no positional write
// (pwrite) and no fsync, and both are needed to overwrite the existing blocks durably.
score::crypto::Expected<std::monostate, DaemonErrorCode> SecureEraseFile(const std::string& path, std::size_t max_size)
{
    if (path.empty())
    {
        return score::crypto::make_unexpected(DaemonErrorCode::kInvalidArgument);
    }

    // O_NOFOLLOW: never overwrite the target of a symbolic link placed where the key file is expected.
    // O_NONBLOCK: a named pipe at this path would otherwise block open() until a reader appears;
    // it has no effect on writes to a regular file.
    FdGuard fd{::open(path.c_str(), O_WRONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)};
    if (fd.Get() < 0)
    {
        if (errno == ENOENT)
        {
            return std::monostate{};
        }
        if ((errno == ELOOP) || (errno == EISDIR) || (errno == ENXIO))
        {
            return StepFailed("SecureEraseFile", "open (not a regular file)", DaemonErrorCode::kInvalidArgument);
        }
        return StepFailed("SecureEraseFile", "open", DaemonErrorCode::kPersistFailed);
    }

    struct stat file_status{};
    if (::fstat(fd.Get(), &file_status) != 0)
    {
        return StepFailed("SecureEraseFile", "fstat", DaemonErrorCode::kPersistFailed);
    }
    if (!S_ISREG(file_status.st_mode))
    {
        return StepFailed("SecureEraseFile", "type check (not a regular file)", DaemonErrorCode::kInvalidArgument);
    }
    if (static_cast<std::uintmax_t>(file_status.st_size) > max_size)
    {
        return StepFailed(
            "SecureEraseFile", "size check (file larger than allowed)", DaemonErrorCode::kInvalidArgument);
    }

    if (!OverwriteWithZeros(fd.Get(), file_status.st_size))
    {
        return StepFailed("SecureEraseFile", "overwrite", DaemonErrorCode::kPersistFailed);
    }
    // Without fsync the zeros may still sit in the page cache when the file is unlinked,
    // and the kernel is then free to drop them without ever writing them to the device.
    if (::fsync(fd.Get()) != 0)
    {
        return StepFailed("SecureEraseFile", "fsync", DaemonErrorCode::kPersistFailed);
    }
    if (!fd.Close())
    {
        return StepFailed("SecureEraseFile", "close", DaemonErrorCode::kPersistFailed);
    }

    if (const auto removed = RemoveFile(path); !removed)
    {
        return StepFailed("SecureEraseFile", "remove", removed.error());
    }

    // Make the unlink itself durable. Otherwise a power loss before the file system commits
    // it brings the file back zero-filled, and the slot reads as occupied by an all-zero key.
    if (!SyncParentDirectory(path))
    {
        return StepFailed("SecureEraseFile", "directory fsync", DaemonErrorCode::kPersistFailed);
    }
    return std::monostate{};
}

score::crypto::Expected<std::monostate, DaemonErrorCode> CreateSecretFile(const std::string& path,
                                                                          score::crypto::span<const std::uint8_t> data)
{
    if (path.empty() || data.empty())
    {
        return score::crypto::make_unexpected(DaemonErrorCode::kInvalidArgument);
    }

    const score::filesystem::Path target_path{path};
    const auto parent = target_path.ParentPath();
    if (!parent.Empty())
    {
        score::filesystem::StandardFilesystem fs{};
        if (!fs.CreateDirectories(parent).has_value())
        {
            return StepFailed("CreateSecretFile", "create directories", DaemonErrorCode::kPersistFailed);
        }
    }

    // O_EXCL with mode 0600: the file is owner-only from the moment it exists, and a stale or
    // planted file (or link) at the temporary name is never reused.
    const std::string temp_path = path + ".tmp." + std::to_string(::getpid());
    FdGuard fd{::open(temp_path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, S_IRUSR | S_IWUSR)};
    if (fd.Get() < 0)
    {
        return StepFailed("CreateSecretFile", "create temporary file", DaemonErrorCode::kPersistFailed);
    }

    // Anything that fails from here on leaves key bytes in the temporary file; wipe it.
    const auto discard_temp = [&temp_path, &data](std::string_view step, DaemonErrorCode code) {
        auto result = StepFailed("CreateSecretFile", step, code);
        static_cast<void>(SecureEraseFile(temp_path, data.size()));
        return result;
    };

    std::size_t written_total = 0U;
    while (written_total < data.size())
    {
        const ssize_t written = ::write(fd.Get(), data.data() + written_total, data.size() - written_total);
        if (written < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return discard_temp("write", DaemonErrorCode::kPersistFailed);
        }
        if (written == 0)
        {
            return discard_temp("write", DaemonErrorCode::kPersistFailed);
        }
        written_total += static_cast<std::size_t>(written);
    }
    if (::fsync(fd.Get()) != 0)
    {
        return discard_temp("fsync", DaemonErrorCode::kPersistFailed);
    }
    if (!fd.Close())
    {
        return discard_temp("close", DaemonErrorCode::kPersistFailed);
    }

    // link() publishes the complete file under its final name and fails with EEXIST when that
    // name is taken, so an occupied key file is never replaced, even by a concurrent writer.
    if (::link(temp_path.c_str(), path.c_str()) != 0)
    {
        return discard_temp("publish",
                            (errno == EEXIST) ? DaemonErrorCode::kKeySlotOccupied : DaemonErrorCode::kPersistFailed);
    }
    // The key file now holds the bytes; the temporary name is only a second link to the same
    // blocks, so removing it must not overwrite them.
    if (::unlink(temp_path.c_str()) != 0)
    {
        return StepFailed("CreateSecretFile", "remove temporary name", DaemonErrorCode::kPersistFailed);
    }
    if (!SyncParentDirectory(path))
    {
        return StepFailed("CreateSecretFile", "directory fsync", DaemonErrorCode::kPersistFailed);
    }
    return std::monostate{};
}

}  // namespace score::crypto::daemon::common::storage

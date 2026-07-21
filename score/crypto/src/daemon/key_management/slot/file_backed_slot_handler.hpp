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

#ifndef SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_FILE_BACKED_SLOT_HANDLER_HPP
#define SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_FILE_BACKED_SLOT_HANDLER_HPP

#include "score/crypto/daemon/key_management/interfaces/i_key_factory.hpp"
#include "score/crypto/daemon/key_management/interfaces/i_key_slot_handler.hpp"

#include <cstddef>
#include <memory>
#include <string_view>
#include <vector>

namespace score::crypto::daemon::key_management
{

/// IKeySlotHandler for file-backed (pure-SW) providers.
///
/// Reads raw key bytes from a file and delegates to IKeyFactory::ImportKey().
/// The local read buffer is securely zeroized immediately after the provider
/// has internalized the material, even on failure.
///
/// Support for encrypted-at-rest files is reserved for future extension.
///
/// One FileBackedSlotHandler is shared across all slots that use the same
/// provider. Per-call slot configuration (file path, algorithm, permissions)
/// comes from the KeySlotConfig argument.
class FileBackedSlotHandler final : public IKeySlotHandler
{
  public:
    /// @param factory  Provider key factory used for ImportKey.
    explicit FileBackedSlotHandler(IKeyFactory::Sptr factory);

    ~FileBackedSlotHandler() override = default;

    FileBackedSlotHandler(const FileBackedSlotHandler&) = delete;
    FileBackedSlotHandler& operator=(const FileBackedSlotHandler&) = delete;
    FileBackedSlotHandler(FileBackedSlotHandler&&) = delete;
    FileBackedSlotHandler& operator=(FileBackedSlotHandler&&) = delete;

    /// Load key from file → ImportKey → zeroize local buffer.
    ///
    /// Steps:
    ///   1. Load deployment descriptor from slot.deployment_path.
    ///   2. Resolve file path from key_properties[kKeyPath].
    ///   3. Read key bytes into a local vector.
    ///   4. Validate: size > 0 and <= kMaxKeyFileSize.
    ///   5. Delegate to IKeyFactory::ImportKey(KeyImportRequest).
    ///   6. Securely zeroize and clear the local buffer (always, even on error).
    [[nodiscard]] score::crypto::Expected<IKeyHandler::Sptr, score::crypto::daemon::common::DaemonErrorCode> LoadKey(
        const KeySlotConfig& slot) override;

    /// Return kOccupied if the key file exists, kEmpty otherwise.
    [[nodiscard]] score::crypto::Expected<score::mw::crypto::KeySlotState,
                                          score::crypto::daemon::common::DaemonErrorCode>
    GetSlotState(const KeySlotConfig& slot) override;

    /// Return slot metadata derived from the KeySlotConfig.
    [[nodiscard]] score::crypto::Expected<score::mw::crypto::KeySlotInfo,
                                          score::crypto::daemon::common::DaemonErrorCode>
    GetSlotInfo(const KeySlotConfig& slot) override;

  private:
    [[nodiscard]] score::crypto::Expected<std::vector<std::uint8_t>, score::crypto::daemon::common::DaemonErrorCode>
    ReadKeyFile(const std::string& file_path) const;

    IKeyFactory::Sptr m_factory;

    /// Maximum key file size to guard against reading unreasonably large files.
    static constexpr std::size_t kMaxKeyFileSize = 8U * 1024U;

    static constexpr std::string_view LOG_PREFIX = "[FILE_BACKED_SLOT_HANDLER]";
};

}  // namespace score::crypto::daemon::key_management

#endif  // SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_FILE_BACKED_SLOT_HANDLER_HPP

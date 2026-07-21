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

#ifndef SCORE_CRYPTO_DAEMON_CONFIG_FLATBUFFER_CONFIG_PARSER_HPP
#define SCORE_CRYPTO_DAEMON_CONFIG_FLATBUFFER_CONFIG_PARSER_HPP

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <variant>

#include "score/crypto/common/types.hpp"
#include "score/crypto/daemon/common/daemon_error.hpp"
#include "score/crypto/daemon/config/inc/config.hpp"

namespace score::crypto::daemon::config::keyslot
{
// Forward declarations for FlatBuffers-generated types
class CryptoConfig;
class KeySlotConfig;
}  // namespace score::crypto::daemon::config::keyslot

namespace score::crypto::daemon::config
{

/// @brief Parser for FlatBuffers-based configuration files.
///
/// Transforms serialized KeySlotConfigFB (from score::crypto::daemon::config::keyslot
/// namespace via FlatBuffers) into KeyConfig objects that the rest of the daemon
/// recognizes.
class FlatBufferConfigParser
{
  public:
    FlatBufferConfigParser() = default;
    ~FlatBufferConfigParser() = default;

    // Delete copy/move — static utility interface only
    FlatBufferConfigParser(const FlatBufferConfigParser&) = delete;
    FlatBufferConfigParser& operator=(const FlatBufferConfigParser&) = delete;
    FlatBufferConfigParser(FlatBufferConfigParser&&) = delete;
    FlatBufferConfigParser& operator=(FlatBufferConfigParser&&) = delete;

    /// @brief Parse FlatBuffers key slot configuration from a file.
    ///
    /// Reads the binary file, validates the FlatBuffers structure, and
    /// populates the output KeyConfig with deserialized slot entries and
    /// app resource mappings.
    ///
    /// @param filepath   Path to the .fbs binary config file
    /// @param out_config Output KeyConfig object to populate
    /// @return Success (monostate) on successful parsing, DaemonErrorCode on failure
    /// @retval kInvalidArgument    File not found, file empty, or buffer too small
    /// @retval kInternal           Invalid FlatBuffers structure or missing required fields
    ///
    /// @note If parsing fails, out_config state is undefined; don't use it.
    static Expected<std::monostate, common::DaemonErrorCode> ParseFromFile(std::string_view filepath,
                                                                           KeyConfig& out_config);

    /// @brief Parse FlatBuffers key slot configuration from a memory buffer.
    ///
    /// Validates the FlatBuffers structure in memory and populates the output
    /// KeyConfig with deserialized entries.
    ///
    /// @param data       Pointer to buffer containing serialized FlatBuffers data
    /// @param size       Size of data buffer in bytes
    /// @param out_config Output KeyConfig object to populate
    /// @return Success (monostate) on successful parsing, DaemonErrorCode on failure
    /// @retval kInvalidArgument    Null pointer, zero size, or invalid FlatBuffers root
    /// @retval kInternal           Missing required fields or invalid file identifier
    ///
    /// @note If parsing fails, out_config state is undefined; don't use it.
    static Expected<std::monostate, common::DaemonErrorCode> ParseFromBuffer(const uint8_t* data,
                                                                             size_t size,
                                                                             KeyConfig& out_config);

  private:
    static constexpr std::string_view LOG_PREFIX = "[FLATBUFFER_PARSER] ";
    static constexpr size_t kMinBufferSize = 4;  // Minimum size to contain FlatBuffers file identifier

    /// @brief Validate FlatBuffers root and file identifier.
    ///
    /// Ensures the buffer contains a valid KeySlotConfigFB root with
    /// the expected file identifier "CCFG" (from score::crypto::daemon::config::keyslot).
    ///
    /// @param data       Pointer to buffer
    /// @param size       Buffer size in bytes
    /// @return Success (monostate) if valid, DaemonErrorCode on validation failure
    /// @retval kInvalidArgument    Null pointer, buffer too small, or invalid identifier
    /// @retval kInternal           Invalid FlatBuffers structure
    static Expected<std::monostate, common::DaemonErrorCode> ValidateBuffer(const uint8_t* data, size_t size);

    /// @brief Parse the key slot configuration from the FlatBuffers root object.
    ///
    /// Extracts the KeySlotConfig from the CryptoConfig root and delegates
    /// parsing of slot entries and app resource entries to helper methods.
    ///
    /// @param root       Pointer to the CryptoConfig FlatBuffers root object
    /// @param out_config Output KeyConfig object to populate
    /// @return Success (monostate) on successful parsing, DaemonErrorCode on failure
    /// @retval kInvalidArgument    Null root or missing key_slot_config
    /// @retval kInternalError      Parsing of entries failed
    static Expected<std::monostate, common::DaemonErrorCode> ParseKeySlotConfig(const keyslot::CryptoConfig* root,
                                                                                KeyConfig& out_config);

    /// @brief Parse slot entries from key slot configuration.
    ///
    /// Iterates through slot entries in the KeySlotConfig and populates
    /// KeyConfig with parsed KeySlotEntry objects.
    ///
    /// @param key_slot_config Pointer to the KeySlotConfig FlatBuffers object
    /// @param out_config      Output KeyConfig object to populate
    /// @return Success (monostate) on successful parsing, DaemonErrorCode on failure
    /// @retval kInternalError  Invalid entry structure or missing required fields
    static Expected<std::monostate, common::DaemonErrorCode> ParseSlotEntries(
        const keyslot::KeySlotConfig* key_slot_config,
        KeyConfig& out_config);

    /// @brief Parse app resource entries from key slot configuration.
    ///
    /// Iterates through app resource entries in the KeySlotConfig and populates
    /// KeyConfig with parsed AppResourceEntry objects.
    ///
    /// @param key_slot_config Pointer to the KeySlotConfig FlatBuffers object
    /// @param out_config      Output KeyConfig object to populate
    /// @return Success (monostate) on successful parsing, DaemonErrorCode on failure
    /// @retval kInternalError  Invalid entry structure or missing required fields
    static Expected<std::monostate, common::DaemonErrorCode> ParseAppResourceEntries(
        const keyslot::KeySlotConfig* key_slot_config,
        KeyConfig& out_config);
};

}  // namespace score::crypto::daemon::config

#endif  // SCORE_CRYPTO_DAEMON_CONFIG_FLATBUFFER_CONFIG_PARSER_HPP

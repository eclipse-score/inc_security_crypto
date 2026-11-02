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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CONFIG_SRC_FLATBUFFER_CONFIG_PARSER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CONFIG_SRC_FLATBUFFER_CONFIG_PARSER_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/config/inc/config.hpp"

namespace score::crypto::daemon::config::keyslot
{
// Forward declarations for FlatBuffers-generated types (key slot config)
class CryptoConfig;
class KeySlotConfig;
// Forward declarations for FlatBuffers-generated types (cert config)
class CertSlotConfig;
class CertSlotEntry;
class TrustStoreEntry;
class AppCertSlotMapping;
class AppTrustStoreMapping;
}  // namespace score::crypto::daemon::config::keyslot

namespace score::crypto::daemon::config
{

class FlatBufferConfigParser;

/// @brief A configuration file read into memory and checked against the "CCFG" envelope.
///
/// Only FlatBufferConfigParser::LoadFile() creates one, so holding a ConfigFile means its
/// bytes have passed validation. Load it once and pass it to each section parser.
class ConfigFile
{
  public:
    /// @brief Pointer to the validated file bytes. Valid for the lifetime of this object.
    const uint8_t* data() const noexcept
    {
        return m_bytes.data();
    }

    /// @brief Number of validated bytes.
    size_t size() const noexcept
    {
        return m_bytes.size();
    }

  private:
    friend class FlatBufferConfigParser;

    explicit ConfigFile(std::vector<uint8_t> bytes) : m_bytes{std::move(bytes)} {}

    std::vector<uint8_t> m_bytes;
};

/// @brief Parser for FlatBuffers-based configuration files.
///
/// Transforms serialized configuration (from score::crypto::daemon::config::keyslot
/// namespace via FlatBuffers) into KeyConfig and CertificateConfig objects that
/// the rest of the daemon recognises.
///
/// The file is read and validated once by LoadFile(). Each section parser then reads
/// only its own section from the loaded file. An absent section is not an error; a
/// present section that cannot be parsed is.
class FlatBufferConfigParser
{
  public:
    FlatBufferConfigParser() = default;
    ~FlatBufferConfigParser() = default;

    FlatBufferConfigParser(const FlatBufferConfigParser&) = delete;
    FlatBufferConfigParser& operator=(const FlatBufferConfigParser&) = delete;
    FlatBufferConfigParser(FlatBufferConfigParser&&) = delete;
    FlatBufferConfigParser& operator=(FlatBufferConfigParser&&) = delete;

    // -----------------------------------------------------------------------
    // File loading and section entry points
    // -----------------------------------------------------------------------

    /// @brief Read a binary config file and validate its envelope.
    ///
    /// @param filepath Path to the generated binary config file (.bin)
    /// @return The validated file, or DaemonErrorCode if it cannot be read or validated
    static Expected<ConfigFile, common::DaemonErrorCode> LoadFile(std::string_view filepath);

    /// @brief Parse the key management section (key_slot_config) from a loaded file.
    ///
    /// @param file       Validated file from LoadFile()
    /// @param out_config Output KeyConfig; replaced only when the section parses fully, so it is
    ///                   left unchanged when the section is absent or fails to parse
    /// @return true if the section was present and parsed, false if the file has no
    ///         key_slot_config, or DaemonErrorCode if the present section is malformed
    static Expected<bool, common::DaemonErrorCode> ParseKeyManagementConfig(const ConfigFile& file,
                                                                            KeyConfig& out_config);

    /// @brief Parse the certificate management section (cert_slot_config) from a loaded file.
    ///
    /// @param file       Validated file from LoadFile()
    /// @param out_config Output CertificateConfig; replaced only when the section parses fully, so it is
    ///                   left unchanged when the section is absent or fails to parse
    /// @return true if the section was present and parsed, false if the file has no
    ///         cert_slot_config, or DaemonErrorCode if the present section is malformed
    static Expected<bool, common::DaemonErrorCode> ParseCertManagementConfig(const ConfigFile& file,
                                                                             CertificateConfig& out_config);

    // -----------------------------------------------------------------------
    // Low-level helpers — key slot config (binary FlatBuffers)
    // -----------------------------------------------------------------------

    /// @brief Parse key slot configuration from a binary FlatBuffers file.
    static Expected<std::monostate, common::DaemonErrorCode> ParseFromFile(std::string_view filepath,
                                                                           KeyConfig& out_config);

    /// @brief Parse key slot configuration from a binary FlatBuffers memory buffer.
    static Expected<std::monostate, common::DaemonErrorCode> ParseFromBuffer(const uint8_t* data,
                                                                             size_t size,
                                                                             KeyConfig& out_config);

  private:
    static constexpr std::string_view LOG_PREFIX = "[FLATBUFFER_PARSER] ";
    static constexpr size_t kMinBufferSize = 8U;

    // -----------------------------------------------------------------------
    // Key slot config helpers
    // -----------------------------------------------------------------------

    /// @brief Check that a buffer is large enough and carries the "CCFG" file identifier.
    /// @param data Start of the buffer.
    /// @param size Length of the buffer in bytes.
    /// @return Success, or kInvalidArgument when the buffer is null, too small, has an unexpected
    ///         identifier, or fails FlatBuffers verification.
    static Expected<std::monostate, common::DaemonErrorCode> ValidateBuffer(const uint8_t* data, size_t size);

    static Expected<std::monostate, common::DaemonErrorCode> ParseKeySlotConfig(const keyslot::CryptoConfig* root,
                                                                                KeyConfig& out_config);

    static Expected<std::monostate, common::DaemonErrorCode> ParseSlotEntries(
        const keyslot::KeySlotConfig* key_slot_config,
        KeyConfig& out_config);

    static Expected<std::monostate, common::DaemonErrorCode> ParseAppKeySlotMappings(
        const keyslot::KeySlotConfig* key_slot_config,
        KeyConfig& out_config);

    // -----------------------------------------------------------------------
    // Cert config helpers
    // -----------------------------------------------------------------------

    static Expected<std::monostate, common::DaemonErrorCode> ParseCertSlotConfig(
        const keyslot::CertSlotConfig* cert_slot_config,
        CertificateConfig& out_config);

    static Expected<std::monostate, common::DaemonErrorCode> ParseCertSlotEntries(
        const keyslot::CertSlotConfig* cert_slot_config,
        CertificateConfig& out_config);

    static Expected<std::monostate, common::DaemonErrorCode> ParseTrustStoreEntries(
        const keyslot::CertSlotConfig* cert_slot_config,
        CertificateConfig& out_config);

    static Expected<std::monostate, common::DaemonErrorCode> ParseAppCertSlotMappings(
        const keyslot::CertSlotConfig* cert_slot_config,
        CertificateConfig& out_config);

    static Expected<std::monostate, common::DaemonErrorCode> ParseAppTrustStoreMappings(
        const keyslot::CertSlotConfig* cert_slot_config,
        CertificateConfig& out_config);
};

}  // namespace score::crypto::daemon::config

#endif  // SCORE_CRYPTO_SRC_DAEMON_CONFIG_SRC_FLATBUFFER_CONFIG_PARSER_HPP

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
#include <variant>

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
class AppCertSlotEntry;
class AppTrustStoreEntry;
}  // namespace score::crypto::daemon::config::keyslot

namespace score::crypto::daemon::config
{

/// @brief Parser for FlatBuffers-based configuration files.
///
/// Transforms serialized configuration (from score::crypto::daemon::config::keyslot
/// namespace via FlatBuffers) into KeyConfig and CertificateConfig objects that
/// the rest of the daemon recognises.
///
/// ### Single-file binary entry point
///
/// Use ParseAll() for the normal daemon startup path. It reads a generated
/// binary FlatBuffers file containing the full crypto stack configuration.
///
/// ### Component-specific entry points
///
/// ParseFrom{File,Buffer} and ParseCertConfigFromFile remain available for
/// callers that need to load a specific configuration section.
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
    // Unified entry point - populates all config sections
    // -----------------------------------------------------------------------

    /// @brief Parse the complete crypto stack configuration from a single file.
    ///
    /// Reads a binary FlatBuffers file containing both configuration sections.
    ///
    /// This is the recommended call site for daemon startup.  Pass the path
    /// obtained from the CRYPTO_CONFIG_FILE environment variable.
    ///
    /// @param filepath    Path to the generated binary config file (.bin)
    /// @param key_config  Output KeyConfig to populate
    /// @param cert_config Output CertificateConfig to populate
    /// @return Success or DaemonErrorCode on failure
    static Expected<std::monostate, common::DaemonErrorCode> ParseAll(std::string_view filepath,
                                                                      KeyConfig& key_config,
                                                                      CertificateConfig& cert_config);

    // -----------------------------------------------------------------------
    // Per-component entry points - dedicated single-section parsers
    //
    // Use these when only one config section is needed, or to make it
    // explicit in Config::ParseConfig() which components are being loaded.
    // Each reads the config file once and extracts only its own section.
    // -----------------------------------------------------------------------

    /// @brief Parse only the key management section (key_slot_config) from a config file.
    ///
    /// Accepts the same binary format as ParseAll(). The cert management section,
    /// if present in the file, is silently ignored.
    ///
    /// Use this in Config::ParseConfig() as the single control point for key
    /// management config loading: removing this call disables key slot loading
    /// without affecting any other component.
    static Expected<std::monostate, common::DaemonErrorCode> ParseKeyManagementConfig(std::string_view filepath,
                                                                                      KeyConfig& out_config);

    /// @brief Parse only the certificate management section (cert_slot_config) from a config file.
    ///
    /// Accepts the same binary format as ParseAll(). The key management section,
    /// if present in the file, is silently ignored.
    ///
    /// Use this in Config::ParseConfig() as the single control point for cert
    /// management config loading: removing this call disables cert slot and trust
    /// store loading without affecting any other component.
    static Expected<std::monostate, common::DaemonErrorCode> ParseCertManagementConfig(std::string_view filepath,
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

    // -----------------------------------------------------------------------
    // Low-level helpers - cert management config (binary FlatBuffers)
    // -----------------------------------------------------------------------

    /// @brief Parse certificate management configuration from a binary FlatBuffers file.
    static Expected<std::monostate, common::DaemonErrorCode> ParseCertConfigFromFile(std::string_view filepath,
                                                                                     CertificateConfig& out_config);

  private:
    static constexpr std::string_view LOG_PREFIX = "[FLATBUFFER_PARSER] ";
    static constexpr size_t kMinBufferSize = 4U;

    // -----------------------------------------------------------------------
    // ParseAll helpers
    // -----------------------------------------------------------------------

    /// Parse both key and cert config from a FlatBuffers binary buffer.
    /// Validates the "CCFG" file identifier before parsing.
    static Expected<std::monostate, common::DaemonErrorCode> ParseAllFromBinary(const uint8_t* data,
                                                                                size_t size,
                                                                                KeyConfig& key_config,
                                                                                CertificateConfig& cert_config);

    // -----------------------------------------------------------------------
    // Key slot config helpers
    // -----------------------------------------------------------------------

    static Expected<std::monostate, common::DaemonErrorCode> ValidateBuffer(const uint8_t* data, size_t size);

    static Expected<std::monostate, common::DaemonErrorCode> ParseKeySlotConfig(const keyslot::CryptoConfig* root,
                                                                                KeyConfig& out_config);

    static Expected<std::monostate, common::DaemonErrorCode> ParseSlotEntries(
        const keyslot::KeySlotConfig* key_slot_config,
        KeyConfig& out_config);

    static Expected<std::monostate, common::DaemonErrorCode> ParseAppKeySlotEntries(
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

    static Expected<std::monostate, common::DaemonErrorCode> ParseAppCertSlotEntries(
        const keyslot::CertSlotConfig* cert_slot_config,
        CertificateConfig& out_config);

    static Expected<std::monostate, common::DaemonErrorCode> ParseAppTrustStoreEntries(
        const keyslot::CertSlotConfig* cert_slot_config,
        CertificateConfig& out_config);
};

}  // namespace score::crypto::daemon::config

#endif  // SCORE_CRYPTO_SRC_DAEMON_CONFIG_SRC_FLATBUFFER_CONFIG_PARSER_HPP

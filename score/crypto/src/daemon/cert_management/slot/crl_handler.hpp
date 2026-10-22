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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_SLOT_CRL_HANDLER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_SLOT_CRL_HANDLER_HPP

#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_slot_config.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/storage/file_io.hpp"

#include <cstdint>
#include <optional>
#include <variant>
#include <vector>

namespace score::crypto::daemon::cert_management
{

/// Manages CRL persistence for a certificate slot via the slot's deployment
/// descriptor [crl] section. CRL data is always stored on the filesystem —
/// PKCS#11 tokens do not have a native CRL object type, and CRLs are public
/// data that requires no hardware protection.
///
/// Used by composition in FileBackedSlotHandler and Pkcs11CertSlotHandler to
/// provide a uniform file-backed CRL implementation regardless of where the
/// certificate itself is stored (filesystem or token).
///
/// Thread safety: This helper has no internal synchronization. Callers must
/// serialize operations for the same slot, including reads that may overlap
/// writes, using the owning slot handler's per-slot operation lock.
class CrlHandler final
{
  public:
    /// Maximum accepted CRL size in bytes, enforced when storing and when loading.
    static constexpr std::size_t kMaxCrlSize = 16U * 1024U * 1024U;

    /// @param writer Write primitive for the CRL file and the descriptor; WriteFile by default.
    explicit CrlHandler(common::storage::FileWriter writer = common::storage::WriteFile);
    ~CrlHandler() = default;

    CrlHandler(const CrlHandler&) = delete;
    CrlHandler& operator=(const CrlHandler&) = delete;
    CrlHandler(CrlHandler&&) = delete;
    CrlHandler& operator=(CrlHandler&&) = delete;

    /// Check whether the slot has an associated CRL file.
    ///
    /// @param slot Configuration of the slot to inspect.
    /// @return True if the descriptor identifies an existing CRL file, false if
    ///         no CRL is configured or the file is absent, or an error if the
    ///         descriptor or filesystem cannot be checked.
    [[nodiscard]] score::crypto::Expected<bool, common::DaemonErrorCode> HasCrl(const CertSlotConfig& slot) const;

    /// Write the CRL bytes to the CRL file and update the descriptor's [crl] section.
    /// Derives the CRL path from the deployment path if not already set.
    /// When @p crl carries metadata, caches it in the descriptor.
    ///
    /// @param slot Configuration of the slot to update.
    /// @param crl CRL bytes, encoding, and optional metadata to store. Empty
    ///            bytes are rejected.
    /// @return std::monostate on success, or an error if the CRL or descriptor
    ///         cannot be written.
    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode> StoreCrl(const CertSlotConfig& slot,
                                                                                            const CrlData& crl);

    /// Remove the CRL file and erase the [crl] section from the descriptor.
    /// Preserves the configured CRL path so it can be reused by a later store.
    ///
    /// @param slot Configuration of the slot to update.
    /// @return std::monostate on success, or an error if the CRL file or
    ///         descriptor cannot be updated.
    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode> ClearCrl(const CertSlotConfig& slot);

    /// Return the metadata cached in the descriptor's [crl] section without reading the CRL file.
    /// An empty value means no CRL is stored or the descriptor holds no usable metadata for it.
    ///
    /// @param slot Configuration of the slot to inspect.
    /// @return CRL metadata when available, an empty optional when the CRL or
    ///         usable metadata is absent, or an error if the descriptor or CRL
    ///         presence cannot be checked.
    [[nodiscard]] score::crypto::Expected<std::optional<score::crypto::CrlMetadata>, common::DaemonErrorCode>
    GetCrlMetadata(const CertSlotConfig& slot) const;

    /// Return the stored CRL bytes together with the format and metadata read from the same
    /// descriptor snapshot, or no value when no CRL is stored.
    ///
    /// @param slot Configuration of the slot to read.
    /// @return A CRL snapshot containing bytes, format, and metadata; an empty
    ///         optional if no CRL is stored; or an error if the descriptor or
    ///         CRL file cannot be read.
    [[nodiscard]] score::crypto::Expected<std::optional<CrlData>, common::DaemonErrorCode> LoadCrlData(
        const CertSlotConfig& slot) const;

  private:
    /// Convert a supported CRL encoding to its descriptor value.
    /// @param format CRL encoding to convert.
    /// @return "der" for DER, otherwise "pem".
    static std::string FormatName(score::crypto::FormatType format);

    /// Write primitive for the CRL file and the descriptor.
    common::storage::FileWriter m_write_file;
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_SLOT_CRL_HANDLER_HPP

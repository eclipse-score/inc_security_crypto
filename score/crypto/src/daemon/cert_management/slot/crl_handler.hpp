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

#include "score/crypto/src/api/common/types.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_slot_config.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"

#include <cstdint>
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
class CrlHandler final
{
  public:
    /// Maximum accepted CRL file size (16 MiB).
    static constexpr std::size_t kMaxCrlSize = 16U * 1024U * 1024U;

    CrlHandler() = default;
    ~CrlHandler() = default;

    CrlHandler(const CrlHandler&) = delete;
    CrlHandler& operator=(const CrlHandler&) = delete;
    CrlHandler(CrlHandler&&) = delete;
    CrlHandler& operator=(CrlHandler&&) = delete;

    /// Return true if the slot's deployment descriptor references an existing CRL file.
    [[nodiscard]] bool HasCrl(const CertSlotConfig& slot) const;

    /// Load raw CRL bytes from the file referenced by the descriptor's [crl] section.
    /// Returns kResourceNotAllocated if no CRL is configured.
    [[nodiscard]] score::crypto::Expected<std::vector<std::uint8_t>, common::DaemonErrorCode> LoadCrl(
        const CertSlotConfig& slot) const;

    /// Write @p data to the CRL file and update the descriptor's [crl] section.
    /// Derives the CRL path from the deployment path if not already set.
    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode> StoreCrl(
        const CertSlotConfig& slot,
        score::crypto::span<const std::uint8_t> data,
        score::crypto::FormatType format);

    /// Remove the CRL file and erase the [crl] section from the descriptor.
    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode> ClearCrl(const CertSlotConfig& slot);

    /// Return the cached crl_next_update epoch from the descriptor's [crl] section.
    /// Returns kResourceNotAllocated if absent.
    [[nodiscard]] score::crypto::Expected<std::int64_t, common::DaemonErrorCode> GetCrlNextUpdate(
        const CertSlotConfig& slot) const;

    /// Return the format (DER or PEM) recorded in the descriptor's [crl] crl_format key.
    /// Returns kDer when the key is absent or the descriptor cannot be loaded.
    [[nodiscard]] score::crypto::FormatType GetCrlFormat(const CertSlotConfig& slot) const;

  private:
    static std::string FormatName(score::crypto::FormatType format);
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_SLOT_CRL_HANDLER_HPP

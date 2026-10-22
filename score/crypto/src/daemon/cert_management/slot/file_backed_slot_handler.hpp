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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_SLOT_FILE_BACKED_SLOT_HANDLER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_SLOT_FILE_BACKED_SLOT_HANDLER_HPP

#include "score/crypto/src/daemon/cert_management/interfaces/i_cert_slot_handler.hpp"
#include "score/crypto/src/daemon/cert_management/slot/crl_handler.hpp"
#include "score/crypto/src/daemon/cert_management/slot/deployment_loader.hpp"
#include "score/crypto/src/daemon/cert_management/slot/deployment_writer.hpp"
#include "score/crypto/src/daemon/common/storage/file_io.hpp"
#include "score/crypto/src/daemon/provider/cert_management/i_cert_parser.hpp"

#include <memory>
#include <mutex>

namespace score::crypto::daemon::cert_management
{
/// File-backed implementation of certificate-slot operations.
///
/// Operations on this handler instance are serialized across certificate and
/// CRL state.
class FileBackedSlotHandler final : public ICertSlotHandler
{
  public:
    /// Maximum accepted certificate size in bytes, enforced when storing and when loading.
    static constexpr std::size_t kMaxCertSize = 64U * 1024U;  // 64 KiB — ample for any X.509 cert

    /// @param parser Parser for certificate and CRL data.
    /// @param writer Write primitive for the certificate file, CRL file, and descriptor; WriteFile by default.
    explicit FileBackedSlotHandler(provider::cert_management::ICertParser::Sptr parser,
                                   common::storage::FileWriter writer = common::storage::WriteFile)
        : m_parser{std::move(parser)}, m_write_file{writer}, m_crl{std::move(writer)}
    {
    }
    ~FileBackedSlotHandler() override = default;

    FileBackedSlotHandler(const FileBackedSlotHandler&) = delete;
    FileBackedSlotHandler& operator=(const FileBackedSlotHandler&) = delete;

    /// @copydoc ICertSlotHandler::LoadCertificate
    score::crypto::Expected<CertObject::Sptr, common::DaemonErrorCode> LoadCertificate(const CertSlotConfig&) override;
    /// @copydoc ICertSlotHandler::GetSlotState
    score::crypto::Expected<score::crypto::CertificateSlotState, common::DaemonErrorCode> GetSlotState(
        const CertSlotConfig&) override;
    /// @copydoc ICertSlotHandler::GetSlotInfo
    score::crypto::Expected<score::crypto::CertificateSlotInfo, common::DaemonErrorCode> GetSlotInfo(
        const CertSlotConfig&) override;
    /// @copydoc ICertSlotHandler::HasCrl
    score::crypto::Expected<bool, common::DaemonErrorCode> HasCrl(const CertSlotConfig&) override;
    /// @copydoc ICertSlotHandler::StoreCertificate
    score::crypto::Expected<std::monostate, common::DaemonErrorCode> StoreCertificate(const CertSlotConfig&,
                                                                                      const CertObject&) override;
    /// @copydoc ICertSlotHandler::ClearSlot
    score::crypto::Expected<std::monostate, common::DaemonErrorCode> ClearSlot(const CertSlotConfig&) override;
    /// @copydoc ICertSlotHandler::StoreCrl
    score::crypto::Expected<std::monostate, common::DaemonErrorCode> StoreCrl(const CertSlotConfig&,
                                                                              const CrlData&) override;
    /// @copydoc ICertSlotHandler::ClearCrl
    score::crypto::Expected<std::monostate, common::DaemonErrorCode> ClearCrl(const CertSlotConfig&) override;
    /// @copydoc ICertSlotHandler::GetCrlMetadata
    score::crypto::Expected<std::optional<score::crypto::CrlMetadata>, common::DaemonErrorCode> GetCrlMetadata(
        const CertSlotConfig&) override;
    /// @copydoc ICertSlotHandler::LoadCrlData
    score::crypto::Expected<std::optional<CrlData>, common::DaemonErrorCode> LoadCrlData(
        const CertSlotConfig&) override;

  private:
    /// Load a certificate while the caller holds m_slot_operation_mutex.
    /// @param slot Configuration of the slot to read.
    /// @return The parsed certificate, or an error if the descriptor, file, or
    ///         certificate cannot be loaded or parsed.
    [[nodiscard]] score::crypto::Expected<CertObject::Sptr, common::DaemonErrorCode> LoadCertificateUnlocked(
        const CertSlotConfig& slot);

    /// Metadata derived by validating @p crl against the slot's certificate; empty when unavailable.
    /// @param slot Configuration of the slot containing the issuer certificate.
    /// @param crl CRL data to validate against that certificate.
    /// @return Validated CRL metadata, or std::nullopt if validation is unavailable or fails.
    std::optional<score::crypto::CrlMetadata> DeriveCrlMetadata(const CertSlotConfig& slot, const CrlData& crl);

    using Handler = CrlHandler;
    /// Serializes certificate and CRL operations on this slot handler instance.
    std::mutex m_slot_operation_mutex;
    provider::cert_management::ICertParser::Sptr m_parser;
    /// Write primitive for the certificate file and the descriptor; m_crl holds its own copy.
    common::storage::FileWriter m_write_file;
    Handler m_crl;
};
}  // namespace score::crypto::daemon::cert_management
#endif

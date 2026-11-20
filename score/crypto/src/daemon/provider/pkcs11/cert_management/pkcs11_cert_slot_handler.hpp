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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PKCS11_CERT_MANAGEMENT_PKCS11_CERT_SLOT_HANDLER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PKCS11_CERT_MANAGEMENT_PKCS11_CERT_SLOT_HANDLER_HPP

#include "score/crypto/src/daemon/cert_management/interfaces/i_cert_slot_handler.hpp"
#include "score/crypto/src/daemon/cert_management/slot/file_backed_crl_storage.hpp"
#include "score/crypto/src/daemon/common/storage/file_io.hpp"
#include "score/crypto/src/daemon/provider/cert_management/i_cert_parser.hpp"

#include <memory>
#include <mutex>
#include <optional>
#include <utility>

namespace score::crypto::daemon::provider::pkcs11
{

namespace daemon_cert_management = ::score::crypto::daemon::cert_management;
namespace daemon_common = ::score::crypto::daemon::common;
namespace daemon_provider_cert = ::score::crypto::daemon::provider::cert_management;

class Pkcs11Module;
class Pkcs11Provider;

/// PKCS#11 implementation of certificate-slot operations.
///
/// The certificate lives as a CKO_CERTIFICATE (CKC_X_509) token object. The token
/// object is located by the label and/or ID recorded in the slot's deployment
/// descriptor ([certificate] pkcs11.label / pkcs11.object_id). CRL data is stored on
/// the filesystem through FileBackedCrlStorage, because PKCS#11 tokens have no CRL
/// object type.
///
/// Only DER certificates are stored on the token. Other encodings are rejected.
///
/// PKCS#11 does not require the label or ID to be unique, so a slot can match several
/// token objects, for example after an interrupted store. Loading then fails with
/// kResourceNotAllocated, and GetSlotState reports the slot as occupied. StoreCertificate
/// and ClearSlot remove every matching object, so a later write or clear leaves exactly one.
/// A token that refuses a second object with the same identity is handled by StoreCertificate:
/// it removes the earlier objects and retries the creation.
///
/// Integrity policy: Pkcs11Provider refuses slots whose integrity_policy is kRequired.
/// This handler performs no integrity check of its own.
///
/// Thread safety: every public operation holds m_slot_operation_mutex for its full
/// duration, including the token session and the descriptor update.
class Pkcs11CertSlotHandler final : public daemon_cert_management::ICertSlotHandler
{
  public:
    /// @param config   Configuration of the slot this handler serves.
    /// @param provider PKCS#11 provider that supplies sessions.
    /// @param module   PKCS#11 module that supplies the function list.
    /// @param parser   Canonical certificate parser.
    /// @param writer   Write primitive for the descriptor and CRL file; WriteFile by default.
    Pkcs11CertSlotHandler(daemon_cert_management::CertSlotConfig config,
                          std::shared_ptr<Pkcs11Provider> provider,
                          std::weak_ptr<Pkcs11Module> module,
                          daemon_provider_cert::ICertParser::Sptr parser,
                          daemon_common::storage::FileWriter writer = daemon_common::storage::WriteFile);
    ~Pkcs11CertSlotHandler() override;

    Pkcs11CertSlotHandler(const Pkcs11CertSlotHandler&) = delete;
    Pkcs11CertSlotHandler& operator=(const Pkcs11CertSlotHandler&) = delete;

    /// @copydoc cert_management::ICertSlotHandler::LoadCertificate
    score::crypto::Expected<daemon_cert_management::CertObject::Sptr, daemon_common::DaemonErrorCode> LoadCertificate()
        override;
    /// @copydoc cert_management::ICertSlotHandler::GetSlotState
    score::crypto::Expected<score::crypto::CertificateSlotState, daemon_common::DaemonErrorCode> GetSlotState()
        override;
    /// @copydoc cert_management::ICertSlotHandler::GetSlotInfo
    score::crypto::Expected<score::crypto::CertificateSlotInfo, daemon_common::DaemonErrorCode> GetSlotInfo() override;
    /// @copydoc cert_management::ICertSlotHandler::HasCrl
    score::crypto::Expected<bool, daemon_common::DaemonErrorCode> HasCrl() override;
    /// @copydoc cert_management::ICertSlotHandler::StoreCertificate
    score::crypto::Expected<std::monostate, daemon_common::DaemonErrorCode> StoreCertificate(
        const daemon_cert_management::CertObject& cert) override;
    /// @copydoc cert_management::ICertSlotHandler::ClearSlot
    score::crypto::Expected<std::monostate, daemon_common::DaemonErrorCode> ClearSlot() override;
    /// @copydoc cert_management::ICertSlotHandler::StoreCrl
    score::crypto::Expected<std::monostate, daemon_common::DaemonErrorCode> StoreCrl(
        const daemon_cert_management::CrlData& crl) override;
    /// @copydoc cert_management::ICertSlotHandler::ClearCrl
    score::crypto::Expected<std::monostate, daemon_common::DaemonErrorCode> ClearCrl() override;
    /// @copydoc cert_management::ICertSlotHandler::GetCrlMetadata
    score::crypto::Expected<std::optional<score::crypto::CrlMetadata>, daemon_common::DaemonErrorCode> GetCrlMetadata()
        override;
    /// @copydoc cert_management::ICertSlotHandler::LoadCrlData
    score::crypto::Expected<std::optional<daemon_cert_management::CrlData>, daemon_common::DaemonErrorCode>
    LoadCrlData() override;

  private:
    /// State query without taking the operation lock; the caller must hold it.
    [[nodiscard]] score::crypto::Expected<score::crypto::CertificateSlotState, daemon_common::DaemonErrorCode>
    GetSlotStateUnlocked();

    /// Certificate load without taking the operation lock; the caller must hold it.
    [[nodiscard]] score::crypto::Expected<daemon_cert_management::CertObject::Sptr, daemon_common::DaemonErrorCode>
    LoadCertificateUnlocked();

    /// Metadata for a CRL whose descriptor caches none, obtained by validating the CRL against the
    /// certificate on the token. Empty when no certificate is stored or validation fails. The caller
    /// must hold the operation lock.
    [[nodiscard]] std::optional<score::crypto::CrlMetadata> DeriveCrlMetadata(
        const daemon_cert_management::CrlData& crl);

    /// Serializes certificate and CRL operations on this slot handler instance.
    std::mutex m_slot_operation_mutex;
    std::shared_ptr<Pkcs11Provider> m_provider;
    std::weak_ptr<Pkcs11Module> m_module;
    daemon_provider_cert::ICertParser::Sptr m_parser;
    /// Write primitive for the descriptor; m_crl holds its own copy.
    daemon_common::storage::FileWriter m_write_file;
    daemon_cert_management::FileBackedCrlStorage m_crl;
};

}  // namespace score::crypto::daemon::provider::pkcs11

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PKCS11_CERT_MANAGEMENT_PKCS11_CERT_SLOT_HANDLER_HPP

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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_INTERFACES_I_CERT_SLOT_HANDLER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_INTERFACES_I_CERT_SLOT_HANDLER_HPP

#include "score/crypto/src/api/common/types.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_object.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_slot_config.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"

#include <span>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <variant>
#include <vector>

namespace score::crypto::daemon::cert_management
{

/// Interface for provider-specific certificate slot operations.
///
/// A slot handler manages the storage backend for one deployment category:
///   - FileBackedSlotHandler : file system (OpenSSL / software provider)
///   - (future) hardware providers implement their own ICertSlotHandler subclass
///
/// LoadCertificate is the primary operation: it retrieves certificate material
/// from the slot and returns a CertObject that owns the parsed form.
///
/// CRL operations are co-located with the certificate slot:
/// the [crl] section of the slot's KV deployment descriptor holds the CRL.
/// ICertSlotHandler is the single management surface for both the certificate
/// and its associated CRL (if any).
///
/// Default implementations of optional methods return kUnsupportedOperation.
/// Implementations that support only read-only certificate material (e.g., a
/// static-provisioning slot) override only LoadCertificate, GetSlotState, and
/// GetSlotInfo.
///
/// Thread safety: individual slot handler instances are not thread-safe.
/// The CertManagementService serializes concurrent access via DataNode locks.
class ICertSlotHandler
{
  public:
    using Sptr = std::shared_ptr<ICertSlotHandler>;

    ICertSlotHandler() = default;

    virtual ~ICertSlotHandler() = default;

    ICertSlotHandler(const ICertSlotHandler&) = delete;
    ICertSlotHandler& operator=(const ICertSlotHandler&) = delete;
    ICertSlotHandler(ICertSlotHandler&&) = delete;
    ICertSlotHandler& operator=(ICertSlotHandler&&) = delete;

    // -----------------------------------------------------------------------
    // Pure virtual — must be implemented by every slot handler
    // -----------------------------------------------------------------------

    /// Load certificate material from the slot and return a handler that owns it.
    ///
    /// For file-backed slots: reads the file referenced in the [certificate]
    /// section of the deployment descriptor, delegates to the injected ICertParser.
    /// For hardware slots: retrieves the certificate object from the secure element.
    ///
    /// The returned CertObject must be transferred to a CertDataNode
    /// (via CertManagementService::RegisterCertMaterial()) immediately; the
    /// caller must not hold a bare reference across yield points.
    ///
    /// Returns kKeySlotEmpty when no certificate has been stored in this slot.
    [[nodiscard]] virtual score::crypto::Expected<CertObject::Sptr, score::crypto::daemon::common::DaemonErrorCode>
    LoadCertificate(const CertSlotConfig& slot) = 0;

    /// Query certificate-slot state (kEmpty or kOccupied).
    ///
    /// Must not load the certificate — for file-backed slots this is a
    /// lightweight existence check (stat) against the deployment descriptor.
    [[nodiscard]] virtual score::crypto::Expected<score::crypto::CertificateSlotState,
                                                  score::crypto::daemon::common::DaemonErrorCode>
    GetSlotState(const CertSlotConfig& slot) = 0;

    /// Return slot metadata (state, subject, issuer, validity, provider).
    ///
    /// May read cached metadata from the [certificate_metadata] section of the
    /// deployment descriptor without fully parsing the certificate file.
    [[nodiscard]] virtual score::crypto::Expected<score::crypto::CertificateSlotInfo,
                                                  score::crypto::daemon::common::DaemonErrorCode>
    GetSlotInfo(const CertSlotConfig& slot) = 0;

    /// True when the slot has an associated CRL stored in its [crl] section.
    ///
    /// For file-backed slots: checks existence of the crl_path key in the
    /// deployment descriptor and verifies the file is present.
    [[nodiscard]] virtual bool HasCrl(const CertSlotConfig& slot) = 0;

    // -----------------------------------------------------------------------
    // Optional — defaulted to kUnsupportedOperation
    // -----------------------------------------------------------------------

    /// Persist a CertObject's certificate material into the slot.
    ///
    /// For file-backed slots: serializes to the format specified in the
    /// deployment descriptor and writes to the path in the [certificate]
    /// section. Updates the [certificate_metadata] section.
    /// For hardware slots: stores the certificate object in the secure element.
    ///
    /// Default: returns kUnsupportedOperation.
    [[nodiscard]] virtual score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    StoreCertificate(const CertSlotConfig& slot, const CertObject& cert);

    /// Erase certificate material (and CRL if present) from the slot.
    ///
    /// After this call, GetSlotState() must return kEmpty and HasCrl() false.
    ///
    /// Default: returns kUnsupportedOperation.
    [[nodiscard]] virtual score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    ClearSlot(const CertSlotConfig& slot);

    // ---- CRL management --------------------------------------------------

    /// Load the raw CRL bytes from the slot's [crl] section.
    ///
    /// Returns the DER or PEM bytes as stored; callers inspect the format via
    /// the cert_deployment_keys::kCrlFormat key in the deployment descriptor.
    ///
    /// Default: returns kUnsupportedOperation.
    [[nodiscard]] virtual score::crypto::Expected<std::vector<uint8_t>, score::crypto::daemon::common::DaemonErrorCode>
    LoadCrl(const CertSlotConfig& slot);

    /// Store raw CRL bytes into the slot's [crl] section.
    ///
    /// crl_data points to caller-owned memory valid for the duration of this call.
    /// The implementation must copy the bytes and write them to the configured path.
    /// Updates cert_deployment_keys::kCrlNextUpdate in the deployment descriptor.
    ///
    /// Consistency model: the operation is two steps — write CRL file, then write
    /// descriptor. Each step is individually atomic (temp-file + rename). If the
    /// descriptor write fails after the file write succeeds, the CRL file is an
    /// orphan that HasCrl() will not surface (it cross-validates file existence
    /// against the descriptor path). The orphan is silently overwritten on the
    /// next StoreCrl call. No explicit rollback is required.
    ///
    /// Default: returns kUnsupportedOperation.
    [[nodiscard]] virtual score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    StoreCrl(const CertSlotConfig& slot, score::crypto::span<const uint8_t> crl_data, score::crypto::FormatType format);

    /// Remove the CRL from the slot's [crl] section.
    ///
    /// After this call, HasCrl() must return false.
    ///
    /// Default: returns kUnsupportedOperation.
    [[nodiscard]] virtual score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    ClearCrl(const CertSlotConfig& slot);

    /// Return the nextUpdate time of the stored CRL as Unix epoch seconds.
    ///
    /// Used by the daemon's CRL refresh scheduler. Returns kUnsupportedOperation
    /// when no CRL is stored (HasCrl() == false).
    ///
    /// Default: returns kUnsupportedOperation.
    [[nodiscard]] virtual score::crypto::Expected<int64_t, score::crypto::daemon::common::DaemonErrorCode>
    GetCrlNextUpdate(const CertSlotConfig& slot);
};

/// Factory function type for creating a slot handler from a slot configuration.
///
/// Defined here so that all components (CertManagementService, TrustStoreManager,
/// ConfigDrivenTrustStoreCatalog) share one canonical type rather than each
/// declaring an identical nested alias.
using CertSlotHandlerFactory = std::function<ICertSlotHandler::Sptr(const CertSlotConfig&)>;

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_INTERFACES_I_CERT_SLOT_HANDLER_HPP

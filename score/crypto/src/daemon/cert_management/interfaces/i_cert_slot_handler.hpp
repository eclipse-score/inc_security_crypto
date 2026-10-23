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

#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/api/types/common.hpp"
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
#include <optional>
#include <variant>
#include <vector>

namespace score::crypto::daemon::cert_management
{

/// Interface for certificate-slot operations.
///
/// A slot handler loads and inspects certificate material for a configured slot.
/// CRL operations for the slot are exposed through the same interface.
///
/// LoadCertificate is the primary operation and returns a CertObject that owns
/// the loaded certificate material.
///
/// Optional operations have default implementations; each method documents its
/// behavior when the operation or requested data is unsupported. Read-only
/// implementations may leave unsupported optional operations at their defaults.
///
/// Thread safety: A handler instance may be shared by concurrent requests.
/// Implementations must serialize operations on the same slot, including reads
/// that must be consistent with writes, and synchronize any provider or backend
/// resources they use. A per-handler operation mutex is suitable. Callers must
/// not assume DataNode access serializes handler calls; certificate-slot nodes
/// allow concurrent access.
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

    /// Load certificate material from the slot and return an owning CertObject.
    ///
    /// The returned CertObject must be transferred to a CertDataNode
    /// (via CertManagementService::RegisterCertMaterial()) immediately; the
    /// caller must not hold a bare reference across yield points.
    ///
    /// @param slot Configuration of the slot to load.
    /// @return The loaded certificate on success, or an error code. Returns
    ///         kKeySlotEmpty when the slot has no certificate.
    [[nodiscard]] virtual score::crypto::Expected<CertObject::Sptr, score::crypto::daemon::common::DaemonErrorCode>
    LoadCertificate(const CertSlotConfig& slot) = 0;

    /// Query certificate-slot state (kEmpty or kOccupied).
    ///
    /// Must not load the certificate.
    ///
    /// @param slot Configuration of the slot to query.
    /// @return The slot state, or an error code on failure.
    [[nodiscard]] virtual score::crypto::Expected<score::crypto::CertificateSlotState,
                                                  score::crypto::daemon::common::DaemonErrorCode>
    GetSlotState(const CertSlotConfig& slot) = 0;

    /// Return slot metadata (state, subject, issuer, validity, provider).
    ///
    /// @param slot Configuration of the slot to inspect.
    /// @return Slot metadata, or an error code on failure.
    [[nodiscard]] virtual score::crypto::Expected<score::crypto::CertificateSlotInfo,
                                                  score::crypto::daemon::common::DaemonErrorCode>
    GetSlotInfo(const CertSlotConfig& slot) = 0;

    /// Check whether a CRL is associated with the slot.
    ///
    /// @param slot Configuration of the slot to query.
    /// @return True if a CRL is associated with the slot, false otherwise, or
    ///         an error code if the presence could not be determined.
    [[nodiscard]] virtual score::crypto::Expected<bool, score::crypto::daemon::common::DaemonErrorCode> HasCrl(
        const CertSlotConfig& slot) = 0;

    // -----------------------------------------------------------------------
    // Optional operations — see each method for its default behavior
    // -----------------------------------------------------------------------

    /// Persist a CertObject's certificate material into the slot.
    ///
    /// @param slot Configuration of the destination slot.
    /// @param cert Certificate material to persist.
    /// @return std::monostate on success, or an error code. The default
    ///         implementation returns kUnsupportedOperation.
    [[nodiscard]] virtual score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    StoreCertificate(const CertSlotConfig& slot, const CertObject& cert);

    /// Erase certificate material (and CRL if present) from the slot.
    ///
    /// After this call, GetSlotState() must return kEmpty and HasCrl() false.
    ///
    /// @param slot Configuration of the slot to clear.
    /// @return std::monostate on success, or an error code. The default
    ///         implementation returns kUnsupportedOperation.
    [[nodiscard]] virtual score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    ClearSlot(const CertSlotConfig& slot);

    // ---- CRL management --------------------------------------------------

    /// Store the CRL associated with the slot.
    ///
    /// @param slot Configuration of the slot to update.
    /// @param crl  CRL bytes, encoding, and optional metadata. The implementation must copy
    ///             whatever it needs before returning.
    /// @return std::monostate on success, or an error code. The default
    ///         implementation returns kUnsupportedOperation.
    [[nodiscard]] virtual score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    StoreCrl(const CertSlotConfig& slot, const CrlData& crl);

    /// Remove the CRL associated with the slot.
    ///
    /// After this call, HasCrl() must return false.
    ///
    /// @param slot Configuration of the slot to update.
    /// @return std::monostate on success, or an error code. The default
    ///         implementation returns kUnsupportedOperation.
    [[nodiscard]] virtual score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    ClearCrl(const CertSlotConfig& slot);

    /// Return the metadata of the stored CRL without reading the CRL itself.
    ///
    /// An empty value means no metadata is available: no CRL is stored, or the stored
    /// CRL has none. Use HasCrl() to tell the two apart.
    ///
    /// @param slot Configuration of the slot to query.
    /// @return The metadata, an empty optional when none is available, or an error
    ///         code. The default implementation returns an empty optional.
    [[nodiscard]] virtual score::crypto::Expected<std::optional<score::crypto::CrlMetadata>,
                                                  score::crypto::daemon::common::DaemonErrorCode>
    GetCrlMetadata(const CertSlotConfig& slot);

    /// Return the stored CRL as one snapshot, or std::nullopt when the slot has none.
    ///
    /// Bytes, format, and metadata describe the same CRL, so an implementation should
    /// read them from one view of its backing store. This is the only way to read CRL
    /// bytes.
    ///
    /// @param slot Configuration of the slot to read.
    /// @return The CRL snapshot, std::nullopt when no CRL is stored, or an error
    ///         code on failure. The default implementation returns kUnsupportedOperation.
    [[nodiscard]] virtual score::crypto::Expected<std::optional<CrlData>,
                                                  score::crypto::daemon::common::DaemonErrorCode>
    LoadCrlData(const CertSlotConfig& slot);
};

/// Factory function type for creating a slot handler from a slot configuration.
///
/// Defined here so that all components (CertManagementService, TrustStoreManager,
/// ConfigDrivenTrustStoreCatalog) share one canonical type rather than each
/// declaring an identical nested alias.
using CertSlotHandlerFactory = std::function<ICertSlotHandler::Sptr(const CertSlotConfig&)>;

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_INTERFACES_I_CERT_SLOT_HANDLER_HPP

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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_INTERFACES_I_CERT_SLOT_MANAGER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_INTERFACES_I_CERT_SLOT_MANAGER_HPP

#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_object.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/data_manager/data_node.hpp"

#include <cstdint>
#include <memory>
#include <optional>

namespace score::crypto::daemon::cert_management
{

/// Read-only view of the certificate slot manager.
///
/// Consumers outside the certificate-management component receive this interface. It exposes the
/// read operations only. Mutations go through CertManagementService, which keeps the trust stores that
/// reference a slot in step with each update.
///
/// Every operation is checked against the slot's access policy for the requesting client.
class ICertSlotManager
{
  public:
    using Sptr = std::shared_ptr<ICertSlotManager>;

    ICertSlotManager() = default;
    virtual ~ICertSlotManager() = default;

    ICertSlotManager(const ICertSlotManager&) = delete;
    ICertSlotManager& operator=(const ICertSlotManager&) = delete;
    ICertSlotManager(ICertSlotManager&&) = delete;
    ICertSlotManager& operator=(ICertSlotManager&&) = delete;

    /// @brief Load the certificate stored in a slot.
    /// @param slot      Slot to read.
    /// @param client_id Client requesting the read; checked against the slot's access policy.
    /// @return The parsed certificate, an access-policy or registry error, or the backend's error.
    [[nodiscard]] virtual score::crypto::Expected<CertObject::Sptr, common::DaemonErrorCode> LoadCertificate(
        CertSlotHandle slot,
        data_manager::ClientId client_id) = 0;

    /// @brief Return the state and descriptive information of a slot.
    /// @param slot      Slot to inspect.
    /// @param client_id Client requesting the read; checked against the slot's access policy.
    /// @return The slot information, an access-policy or registry error, or the backend's error.
    [[nodiscard]] virtual score::crypto::Expected<score::crypto::CertificateSlotInfo, common::DaemonErrorCode>
    GetSlotInfo(CertSlotHandle slot, data_manager::ClientId client_id) = 0;

    /// @brief Report whether a slot has a stored CRL.
    /// @param slot      Slot to inspect.
    /// @param client_id Client requesting the read; checked against the slot's access policy.
    /// @return True when a CRL is stored, an access-policy or registry error, or the backend's error.
    [[nodiscard]] virtual score::crypto::Expected<bool, common::DaemonErrorCode> HasCrl(
        CertSlotHandle slot,
        data_manager::ClientId client_id) = 0;

    /// @brief Load the slot's CRL as an immutable snapshot.
    /// @param slot      Slot to read.
    /// @param client_id Client requesting the read; checked against the slot's access policy.
    /// @return The snapshot, or a null pointer when the slot has no CRL; an access-policy or registry error,
    ///         or the backend's error.
    [[nodiscard]] virtual score::crypto::Expected<CrlData::Sptrc, common::DaemonErrorCode> LoadCrlData(
        CertSlotHandle slot,
        data_manager::ClientId client_id) = 0;

    /// @brief Return the metadata of the slot's CRL from the cached entry, without reading the CRL itself.
    /// @param slot      Slot to inspect.
    /// @param client_id Client requesting the read; checked against the slot's access policy.
    /// @return The metadata, an empty optional when none is available, or an error.
    [[nodiscard]] virtual score::crypto::Expected<std::optional<score::crypto::CrlMetadata>, common::DaemonErrorCode>
    GetCrlMetadata(CertSlotHandle slot, data_manager::ClientId client_id) = 0;

    /// @brief Return the next-update time of the slot's CRL.
    /// @param slot      Slot to inspect.
    /// @param client_id Client requesting the read; checked against the slot's access policy.
    /// @return The next-update time as Unix epoch seconds, kResourceNotAllocated when no value is available, or an
    ///         access-policy, registry, or backend error.
    [[nodiscard]] virtual score::crypto::Expected<int64_t, common::DaemonErrorCode> GetCrlNextUpdate(
        CertSlotHandle slot,
        data_manager::ClientId client_id) = 0;
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_INTERFACES_I_CERT_SLOT_MANAGER_HPP

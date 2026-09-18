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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_QUERY_CERT_OBJECT_SERIALIZER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_QUERY_CERT_OBJECT_SERIALIZER_HPP

#include "score/crypto/src/daemon/cert_management/interfaces/cert_object.hpp"
#include "score/crypto/src/daemon/cert_management/slot/cert_slot_manager.hpp"
#include "score/crypto/src/daemon/cert_management/truststore/trust_store_manager.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/data_manager/data_node.hpp"

#include <cstdint>
#include <optional>
#include <vector>

// Forward-declare to avoid pulling in cert_management_service.hpp from the header.
namespace score::crypto::daemon::cert_management
{
class CertManagementService;
}

namespace score::crypto::daemon::cert_management::query
{

/// @brief Serialize a CertObject's chain metadata into IPC response parameters.
///
/// Wire layout (15 params, indices 0–14):
///   [0] subject (OwnedString), [1] issuer (OwnedString),
///   [2] not_before_epoch_s (uint64), [3] not_after_epoch_s (uint64),
///   [4] is_ca (uint8), [5] skid (OwnedBuffer), [6] akid (OwnedBuffer),
///   [7] serial_number_hex (OwnedString), [8] SHA-256 fingerprint (OwnedBuffer 32B),
///   [9] has_crl (uint8), [10] CRL fingerprint (OwnedBuffer 32B),
///   [11] issuer fingerprint (OwnedBuffer 32B), [12] thisUpdate (int64 encoded as uint64),
///   [13] nextUpdate (int64 encoded as uint64), [14] cRLNumber (uint64).
///
/// This is the canonical layout for the mediator's GET_CERTIFICATE_OBJECT op,
/// defined exactly once here.
common::ResponseParameters SerializeCertObject(const CertObject& cert,
                                               std::optional<score::crypto::CrlMetadata> crl_metadata = std::nullopt);

/// @brief Serialize certificate slot state + CRL metadata into IPC response parameters.
///
/// Wire layout (2 params):
///   [0] slot state (uint8, CertificateSlotState), [1] has_crl (uint8)
///
/// Returns an error if GetSlotInfo fails. Used by the mediator's
/// GET_CERT_SLOT_OBJECT handler.
score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode>
SerializeCertSlotInfo(CertSlotManager& mgr, CertSlotHandle slot, data_manager::ClientId client_id);

/// @brief Serialize trust store member snapshot into IPC response parameters.
///
/// Resolves per-client slot DataNodeIds from each member's canonical slot handle
/// via @p service; members whose slot cannot be resolved are silently omitted
/// rather than failing the whole response.
///
/// Wire layout: [0] count N (uint64), then for each member i in [0, N) (7 params):
///   [1+i*7+0] slot_node_id (uint64), [1+i*7+1] fingerprint (OwnedBuffer 32B),
///   [1+i*7+2] subject (OwnedString),  [1+i*7+3] issuer (OwnedString),
///   [1+i*7+4] serial_number (OwnedString), [1+i*7+5] kind (uint8),
///   [1+i*7+6] is_enabled (uint8)
common::ResponseParameters SerializeTrustStoreMembers(const std::vector<TrustStoreManager::MemberSnapshot>& snapshot,
                                                      CertManagementService& service,
                                                      std::uint64_t client_id);

}  // namespace score::crypto::daemon::cert_management::query

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_QUERY_CERT_OBJECT_SERIALIZER_HPP

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
#include "score/crypto/src/daemon/cert_management/interfaces/i_cert_slot_handler.hpp"
#include "score/crypto/src/daemon/cert_management/truststore/trust_store_manager.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"

#include <cstdint>
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
/// Wire layout (9 params, indices 0–8):
///   [0] subject (OwnedString), [1] issuer (OwnedString),
///   [2] not_before_epoch_s (uint64), [3] not_after_epoch_s (uint64),
///   [4] is_ca (uint8), [5] skid (OwnedBuffer), [6] akid (OwnedBuffer),
///   [7] serial_number_hex (OwnedString), [8] SHA-256 fingerprint (OwnedBuffer 32B)
///
/// This is the canonical layout for GET_CERTIFICATE_OBJECT and CERT_GET_METADATA.
/// Both the mediator typed-object handler and the cert management executor use this
/// function so the format is defined exactly once.
common::ResponseParameters SerializeCertObject(const CertObject& cert);

/// @brief Serialize certificate slot state + CRL metadata into IPC response parameters.
///
/// Wire layout (3 params):
///   [0] slot state (uint8, CertificateSlotState), [1] has_crl (uint8),
///   [2] crl_next_update_epoch (uint64, 0 if no CRL)
///
/// Returns an error if GetSlotInfo fails. Both the mediator typed-object handler
/// and the cert management executor use this function.
score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> SerializeCertSlotInfo(
    ICertSlotHandler& handler,
    const CertSlotConfig& config);

/// @brief Serialize trust store member snapshot into IPC response parameters.
///
/// Resolves per-client slot DataNodeIds via @p service; members whose slot cannot
/// be resolved are silently omitted rather than failing the whole response.
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

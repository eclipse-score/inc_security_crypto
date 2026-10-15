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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_QUERY_CERT_OBJECT_RESPONSE_BUILDER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_QUERY_CERT_OBJECT_RESPONSE_BUILDER_HPP

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

/// @brief Build a CertObject's chain metadata into an IPC response payload.
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
///
/// The subject and issuer DNs are the only fields of unbounded size (X.509
/// does not cap Name length). Returns kResponseTooLarge instead of an
/// oversized payload if the built response exceeds
/// common::kMaxResponsePayloadBytes.
score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> BuildCertObjectResponse(
    const CertObject& cert,
    std::optional<score::crypto::CrlMetadata> crl_metadata = std::nullopt);

/// @brief Build certificate slot state + CRL metadata into an IPC response payload.
///
/// Wire layout (2 params):
///   [0] slot state (uint8, CertificateSlotState), [1] has_crl (uint8)
///
/// Returns an error if GetSlotInfo fails. Used by the mediator's
/// GET_CERT_SLOT_OBJECT handler. Always small and fixed-size; no payload
/// budget check needed.
score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode>
BuildCertSlotInfoResponse(CertSlotManager& mgr, CertSlotHandle slot, data_manager::ClientId client_id);

/// @brief Build the lightweight list of a trust store's occupied member slot IDs.
///
/// Phase 1 of the two-call trust-store query pattern: the caller first fetches
/// just the member identities (no subject/issuer/serial resolution), then
/// fetches each member's full detail individually via
/// BuildTrustStoreMemberObjectResponse. Per-entry cost is a single uint64, so
/// this stays within budget even for a trust store with many members.
///
/// Wire layout: [0] count N (uint64), then N entries of
///   [1+i] slot_node_id (uint64)
///
/// Member count is configuration-driven and not bounded by this component, so
/// this still returns kResponseTooLarge rather than an oversized payload in
/// the case of an extremely large trust store.
///
/// @param slots     Occupied member slot handles, e.g. from
///                  TrustStoreManager::GetMemberSlotHandles.
/// @param service   Resolves each slot handle to a per-client DataNodeId.
/// @param client_id Calling client, used for slot resolution.
score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> BuildTrustStoreMemberIdListResponse(
    const std::vector<CertSlotHandle>& slots,
    CertManagementService& service,
    std::uint64_t client_id);

/// @brief Build a single trust store member's detail into an IPC response payload.
///
/// Phase 2 of the two-call trust-store query pattern (see
/// BuildTrustStoreMemberIdListResponse).
///
/// Wire layout (7 params):
///   [0] slot_node_id (uint64), [1] fingerprint (OwnedBuffer 32B),
///   [2] subject (OwnedString), [3] issuer (OwnedString),
///   [4] serial_number (OwnedString), [5] kind (uint8),
///   [6] status (uint8, MemberStatus)
///
/// Subject/issuer are unbounded like BuildCertObjectResponse, so this is
/// budget-checked the same way and returns kResponseTooLarge rather than an
/// oversized payload.
///
/// @param member    Snapshot for the single member being queried, e.g. from
///                  TrustStoreManager::GetMemberSnapshot.
/// @param service   Resolves the member's slot handle to a per-client DataNodeId.
/// @param client_id Calling client, used for slot resolution.
score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> BuildTrustStoreMemberObjectResponse(
    const TrustStoreManager::MemberSnapshot& member,
    CertManagementService& service,
    std::uint64_t client_id);

}  // namespace score::crypto::daemon::cert_management::query

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_QUERY_CERT_OBJECT_RESPONSE_BUILDER_HPP

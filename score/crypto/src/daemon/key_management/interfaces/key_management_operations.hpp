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

#ifndef SCORE_CRYPTO_SRC_DAEMON_KEY_MANAGEMENT_INTERFACES_KEY_MANAGEMENT_OPERATIONS_HPP
#define SCORE_CRYPTO_SRC_DAEMON_KEY_MANAGEMENT_INTERFACES_KEY_MANAGEMENT_OPERATIONS_HPP

#include "score/crypto/src/daemon/common/types.hpp"

namespace score::crypto::daemon::key_management::operations
{

using OperationAction = common::OperationAction;

/// @brief Operation codes for key management requests forwarded to providers.
///
/// Codes are spaced to allow future insertions without renumbering
/// existing operations.
///
/// Note: CTX_CREATE and RESOLVE_RESOURCE are mediator-level operations
/// defined in mediator/mediator_operations.hpp, not provider operations.

// KEY_GENERATE (ephemeral)
// Request:  data_node_id = context_id,
//           param[0]: string — key algorithm (e.g., "AES-256", "HMAC-SHA256")
//           param[1]: uint32 — permissions bitmask (KeyOperationPermission);
//                              for an asymmetric key this governs the private half
//           param[2]: uint32 — public-half permissions bitmask (optional, asymmetric
//                              only); absent means the public half is unrestricted
// Response: status_code (SUCCESS/error)
//           param[0]: uint64 — daemon-assigned ephemeral key resource id
//           param[1]: uint16 — primary provider id (optional)
// Effect:   Generates ephemeral key material, stores in daemon key pool, ref_count = 1
inline constexpr OperationAction KEY_GENERATE = 0x10;

inline constexpr OperationAction KEY_GENERATE_TO_SLOT = 0x11;
inline constexpr OperationAction KEY_PERSIST = 0x12;

// KEY_DERIVE
// Request:  data_node_id = context_id,
//           param[0]: uint64 — source key resource id
//           param[1]: string — derived-key algorithm
//           param[2]: uint32 — permissions bitmask (KeyOperationPermission)
//           param[3..10]: KDF algorithm, salt, label, seed, and optional KDF parameters
// Response: status_code (SUCCESS/error)
//           param[0]: uint64 — daemon-assigned ephemeral key resource id
//           param[1]: uint16 — primary provider id
// Effect:   Derives ephemeral key material. A non-exportable source cannot produce an exportable derived key.
inline constexpr OperationAction KEY_DERIVE = 0x20;
inline constexpr OperationAction KEY_DERIVE_TO_SLOT = 0x21;

inline constexpr OperationAction KEY_AGREE = 0x30;
inline constexpr OperationAction KEY_AGREE_TO_SLOT = 0x31;

// KEY_GET_ENCAPSULATION_SIZE
// Request:  data_node_id = context_id,
//           param[0]: string — KEM algorithm
//           param[1]: uint64 — peer public-key resource id
// Response: status_code (SUCCESS/error)
//           param[0]: uint64 — required ciphertext size
// Effect:   Returns the ciphertext capacity without creating key material.
inline constexpr OperationAction KEY_GET_ENCAPSULATION_SIZE = 0x32;

// KEY_ENCAPSULATE
// Request:  data_node_id = context_id,
//           param[0]: string — KEM algorithm
//           param[1]: uint64 — peer public-key resource id
//           param[2]: uint64 — caller ciphertext capacity
// Response: status_code (SUCCESS/error)
//           param[0]: buffer — ciphertext
//           param[1]: uint64 — daemon-assigned shared-secret resource id
//           param[2]: uint16 — primary provider id
// Effect:   Creates an ephemeral, non-exportable, derive-only shared secret.
inline constexpr OperationAction KEY_ENCAPSULATE = 0x33;

// KEY_DECAPSULATE
// Request:  data_node_id = context_id,
//           param[0]: string — KEM algorithm
//           param[1]: uint64 — private-key resource id
//           param[2]: buffer — ciphertext
// Response: status_code (SUCCESS/error)
//           param[0]: uint64 — daemon-assigned shared-secret resource id
//           param[1]: uint16 — primary provider id
// Effect:   Creates an ephemeral, non-exportable, derive-only shared secret.
inline constexpr OperationAction KEY_DECAPSULATE = 0x34;

inline constexpr OperationAction KEY_WRAP = 0x40;
inline constexpr OperationAction KEY_GET_WRAP_SIZE = 0x41;
inline constexpr OperationAction KEY_UNWRAP = 0x50;
inline constexpr OperationAction KEY_UNWRAP_TO_SLOT = 0x51;

// KEY_IMPORT
// Request:  data_node_id = context_id,
//           param[0]: string — key algorithm
//           param[1]: buffer — encoded key material
//           param[2]: uint8 — key format (FormatType)
//           param[3]: uint32 — permissions bitmask (KeyOperationPermission)
// Response: status_code (SUCCESS/error)
//           param[0]: uint64 — daemon-assigned ephemeral key resource id
//           param[1]: uint16 — primary provider id
// Effect:   Imports ephemeral key material into the daemon key pool, ref_count = 1.
inline constexpr OperationAction KEY_IMPORT = 0x60;
inline constexpr OperationAction KEY_IMPORT_TO_SLOT = 0x61;

// KEY_LOAD
// Request:  data_node_id = context_id,
//           param[0]: uint64 — slot resource id (from ResolveResource with kKeySlot)
// Response: status_code (SUCCESS/error)
//           param[0]: uint64 — daemon-assigned ephemeral key resource id (live key material)
//           param[1]: uint16 — primary provider id (optional)
// Effect:   Loads key material from the specified key slot into an ephemeral key,
//           stores in daemon key pool with ref_count = 1.
//           The slot must contain key material (state != kEmpty).
inline constexpr OperationAction KEY_LOAD = 0x70;

inline constexpr OperationAction KEY_EXPORT = 0x80;
inline constexpr OperationAction KEY_GET_EXPORT_SIZE = 0x81;
inline constexpr OperationAction KEY_SLOT_INFO = 0xB0;
inline constexpr OperationAction KEY_CLEAR = 0xE0;

// KEY_RELEASE
// Request:  data_node_id = context_id,
//           param[0]: uint64 — resource id to release
// Response: status_code (SUCCESS/error)
//           no output parameters
// Effect:   Decrements ref-count; frees key material when ref_count reaches 0
inline constexpr OperationAction KEY_RELEASE = 0xF0;

inline constexpr OperationAction KEY_MGMT_CUSTOM_OP_START = 1 << (std::numeric_limits<OperationAction>::digits - 1);

}  // namespace score::crypto::daemon::key_management::operations

#endif  // SCORE_CRYPTO_SRC_DAEMON_KEY_MANAGEMENT_INTERFACES_KEY_MANAGEMENT_OPERATIONS_HPP

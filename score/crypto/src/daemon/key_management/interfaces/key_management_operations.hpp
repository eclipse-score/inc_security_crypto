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

#ifndef SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_KEY_MANAGEMENT_OPERATIONS_HPP
#define SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_KEY_MANAGEMENT_OPERATIONS_HPP

#include "score/crypto/daemon/common/types.hpp"

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
//           param[1]: uint32 — permissions bitmask (KeyOperationPermission)
// Response: status_code (SUCCESS/error)
//           param[0]: uint64 — daemon-assigned ephemeral key resource id
//           param[1]: uint16 — primary provider id (optional)
// Effect:   Generates ephemeral key material, stores in daemon key pool, ref_count = 1
inline constexpr OperationAction KEY_GENERATE = 0x10;

inline constexpr OperationAction KEY_GENERATE_TO_SLOT = 0x11;
inline constexpr OperationAction KEY_PERSIST = 0x12;
inline constexpr OperationAction KEY_DERIVE = 0x20;
inline constexpr OperationAction KEY_DERIVE_TO_SLOT = 0x21;
inline constexpr OperationAction KEY_AGREE = 0x30;
inline constexpr OperationAction KEY_AGREE_TO_SLOT = 0x31;
inline constexpr OperationAction KEY_WRAP = 0x40;
inline constexpr OperationAction KEY_GET_WRAP_SIZE = 0x41;
inline constexpr OperationAction KEY_UNWRAP = 0x50;
inline constexpr OperationAction KEY_UNWRAP_TO_SLOT = 0x51;
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

#endif  // SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_KEY_MANAGEMENT_OPERATIONS_HPP

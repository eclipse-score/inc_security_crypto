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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_CERT_MANAGEMENT_CERT_MANAGEMENT_OPERATIONS_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_CERT_MANAGEMENT_CERT_MANAGEMENT_OPERATIONS_HPP

#include "score/crypto/src/daemon/common/types.hpp"
#include <limits>

namespace score::crypto::daemon::provider::cert_management
{
using OperationAction = common::OperationAction;
inline constexpr OperationAction CERT_PARSE = 0x10U;
inline constexpr OperationAction CERT_PARSE_CHAIN = 0x11U;
inline constexpr OperationAction CERT_SAVE = 0x12U;
inline constexpr OperationAction CERT_GET_METADATA = 0x13U;
inline constexpr OperationAction CERT_LOAD = 0x20U;
inline constexpr OperationAction CERT_EXPORT = 0x30U;
inline constexpr OperationAction CERT_GET_EXPORT_SIZE = 0x31U;
inline constexpr OperationAction CERT_CONVERT = 0x32U;
inline constexpr OperationAction CERT_GET_CONVERT_SIZE = 0x33U;
inline constexpr OperationAction CERT_CLEAR = 0x40U;
inline constexpr OperationAction CERT_SLOT_INFO = 0x50U;
inline constexpr OperationAction CERT_PUBLIC_KEY = 0x60U;
inline constexpr OperationAction CERT_DELETE_EXPIRED = 0x70U;
inline constexpr OperationAction CRL_IMPORT = 0x80U;
inline constexpr OperationAction CRL_DELETE = 0x81U;
inline constexpr OperationAction CRL_DELETE_EXPIRED = 0x82U;
inline constexpr OperationAction OCSP_REQUEST = 0x90U;
inline constexpr OperationAction TRUST_STORE_ADD_CERT = 0xC0U;
inline constexpr OperationAction TRUST_STORE_REMOVE_CERT = 0xC1U;
inline constexpr OperationAction TRUST_STORE_ENABLE_CERT = 0xC2U;
inline constexpr OperationAction TRUST_STORE_DISABLE_CERT = 0xC3U;
inline constexpr OperationAction TRUST_STORE_ACK_UPDATE = 0xC4U;
inline constexpr OperationAction TRUST_STORE_REMOVE_CERT_BY_ID = 0xC5U;      // remove by cert node_id (lib resolves fp)
inline constexpr OperationAction TRUST_STORE_IMPORT_CRL_FOR_MEMBER = 0xC6U;  // fingerprint + CRL bytes → exclusive slot

inline constexpr OperationAction CERT_RELEASE = 0xF0U;

// Provider-specific operation IDs must be >= CUSTOM_OP_START.
inline constexpr OperationAction CUSTOM_OP_START =
    static_cast<OperationAction>(1U << (std::numeric_limits<OperationAction>::digits - 1));

}  // namespace score::crypto::daemon::provider::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_CERT_MANAGEMENT_CERT_MANAGEMENT_OPERATIONS_HPP

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
#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_HANDLER_OPERATIONS_CERT_VERIFICATION_OPERATIONS_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_HANDLER_OPERATIONS_CERT_VERIFICATION_OPERATIONS_HPP

#include "score/crypto/src/daemon/common/types.hpp"
#include <limits>

namespace score::crypto::daemon::provider::cert_verification
{
using OperationAction = common::OperationAction;

// CERT:VERIFICATION compute operations
inline constexpr OperationAction CERT_VERIFY = 0xB0U;
inline constexpr OperationAction CERT_GET_VERIFIED_CHAIN_EXPORT_SIZE = 0xB1U;
inline constexpr OperationAction CERT_EXPORT_VERIFIED_CHAIN = 0xB2U;
inline constexpr OperationAction CERT_GET_VERIFIED_CERT_EXPORT_SIZE = 0xB3U;
inline constexpr OperationAction CERT_EXPORT_VERIFIED_CERT = 0xB4U;

// CERT:VERIFICATION context setters (accumulated before CERT_VERIFY)
inline constexpr OperationAction CERT_VERIFY_SET_LEAF = 0xD0U;
inline constexpr OperationAction CERT_VERIFY_SET_CHAIN = 0xD1U;
inline constexpr OperationAction CERT_VERIFY_SET_TRUST_STORE = 0xD2U;
inline constexpr OperationAction CERT_VERIFY_SET_TRUSTED = 0xD3U;
inline constexpr OperationAction CERT_VERIFY_SET_POLICY = 0xD4U;
inline constexpr OperationAction CERT_VERIFY_SET_ADDITIONAL = 0xD5U;
inline constexpr OperationAction CERT_VERIFY_SET_VERIFICATION_TIME = 0xD6U;
inline constexpr OperationAction CERT_VERIFY_SET_REVOCATION_POLICY = 0xD7U;
inline constexpr OperationAction CERT_VERIFY_SET_EVIDENCE_MODE = 0xD8U;
inline constexpr OperationAction CERT_GET_SELECTED_CRL_METADATA = 0xB5U;

// Provider-specific operation IDs must be >= CUSTOM_OP_START.
inline constexpr OperationAction CUSTOM_OP_START =
    static_cast<OperationAction>(1U << (std::numeric_limits<OperationAction>::digits - 1));

}  // namespace score::crypto::daemon::provider::cert_verification

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_HANDLER_OPERATIONS_CERT_VERIFICATION_OPERATIONS_HPP

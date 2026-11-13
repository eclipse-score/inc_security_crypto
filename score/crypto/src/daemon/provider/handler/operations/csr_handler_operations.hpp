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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_HANDLER_OPERATIONS_CSR_HANDLER_OPERATIONS_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_HANDLER_OPERATIONS_CSR_HANDLER_OPERATIONS_HPP

#include "score/crypto/src/daemon/common/types.hpp"

namespace score::crypto::daemon::provider::handler::csr_handler_operations
{
// CTX_CREATE: [0]="CSR_GENERATION", [1]=registry signature algorithm,
// [2]=optional provider preference, [3]=uint64 key_node_id (required).
// Legacy CSR_GENERATE: [0]=DER SEQUENCE { subject Name, attributes SET OF Attribute },
// [1]=optional writable DER output span. The client attaches DataShm(In) and
// DataShm(InOut) descriptors; the SHM handler resolves them before dispatch.
// This SCORE parameter envelope is not a full PKCS#10 request. Only standard
// extensionRequest and challengePassword attributes are allowed. No key,
// signature algorithm, version, issuer or submission metadata is client supplied.
// Response with output span: one uint64 written-byte count. DER is in the
// caller's output span, not the control-plane response.
// Direct one-input request: one OwnedBuffer containing the complete DER CSR.
// No client-selected prehashed mode: the provider signs CertificationRequestInfo.
inline constexpr common::OperationAction CSR_GENERATE = 1U;
// CSR_PUBLIC_KEY_INFO: optional [0]=writable SHM output. Returns only DER
// SubjectPublicKeyInfo of the already bound key, never private-key bytes.
// Retained for direct callers; the production frontend never needs this query.
// Output form returns a uint64 byte count; direct zero-input form returns DER.
inline constexpr common::OperationAction CSR_PUBLIC_KEY_INFO = 2U;
// Distinct action: bounded version-1 SCR1 FlatBuffer, never legacy DER.
// Only neutral subject/extensions/password are accepted. The bound key owns
// extension context, algorithm, signing and verification in the daemon.
inline constexpr common::OperationAction CSR_GENERATE_NATIVE = 3U;
inline constexpr std::size_t kMaxInputDerBytes = 16384U;
inline constexpr std::size_t kMaxSubjectEntries = 64U;
inline constexpr std::size_t kMaxExtensions = 32U;
inline constexpr std::size_t kMaxOidBytes = 128U;
inline constexpr std::size_t kMaxValueBytes = 2048U;
inline constexpr std::size_t kMaxChallengePasswordBytes = 255U;
// Retain the tested DER bound, including direct inline-response compatibility.
inline constexpr std::size_t kMaxDerBytes = common::kMaxResponsePayloadBytes;
}  // namespace score::crypto::daemon::provider::handler::csr_handler_operations

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_HANDLER_OPERATIONS_CSR_HANDLER_OPERATIONS_HPP

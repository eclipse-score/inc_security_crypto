/*******************************************************************************
 *
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
 *******************************************************************************
 */

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CONTEXT_CRL_VALIDATION_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CONTEXT_CRL_VALIDATION_HPP

#include "score/crypto/src/daemon/cert_management/interfaces/cert_object.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_types.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/cert_management/i_cert_parser.hpp"

namespace score::crypto::daemon::cert_management
{

/// @brief Validate CRL bytes against the certificate that issued them.
///
/// The parser checks that the CRL parses, that its issuer matches the issuer certificate, and that its signature
/// verifies. On success the returned value carries the CRL bytes, the format, and the metadata the parser extracted.
/// Only DER and PEM encodings are accepted; the format is taken from the caller and never defaulted.
///
/// @param parser CRL validator. Must not be null.
/// @param issuer Certificate whose key signed the CRL.
/// @param crl_bytes Encoded CRL.
/// @param crl_format Encoding of @p crl_bytes; kDer or kPem.
/// @return The validated CRL, kInvalidArgument for an unsupported format, or the parser's error.
score::crypto::Expected<CrlData, common::DaemonErrorCode> ValidateCrlAgainstIssuer(
    provider::cert_management::ICertParser& parser,
    const CertObject& issuer,
    score::crypto::span<const std::uint8_t> crl_bytes,
    score::crypto::FormatType crl_format);

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CONTEXT_CRL_VALIDATION_HPP

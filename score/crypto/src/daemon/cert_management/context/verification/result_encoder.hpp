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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CONTEXT_VERIFICATION_RESULT_ENCODER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CONTEXT_VERIFICATION_RESULT_ENCODER_HPP

#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_object.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/cert_management/i_cert_parser.hpp"

#include <cstdint>
#include <memory>
#include <vector>

namespace score::crypto::daemon::cert_management
{

/// @brief Encodes the outputs of a verification for the client: certificates in DER or PEM, and selected CRL metadata
///        in the CrlMetadataWireLayout encoding.
class VerifiedResultEncoder final
{
  public:
    /// @brief Construct the encoder.
    /// @param parser Parser that encodes certificates. Must be non-null.
    explicit VerifiedResultEncoder(provider::cert_management::ICertParser::Sptr parser);

    /// @brief Encode one certificate.
    /// @param certificate Certificate to encode.
    /// @param format Requested encoding; kDer or kPem.
    /// @return The encoded bytes, kInvalidArgument for any other format, or the parser's error.
    [[nodiscard]] score::crypto::Expected<std::vector<std::uint8_t>, common::DaemonErrorCode> EncodeCertificate(
        const CertObject& certificate,
        score::crypto::FormatType format) const;

    /// @brief Encode the certificates of a chain in order and concatenate the encodings.
    /// @param chain Certificates to encode, leaf first. Entries must be non-null.
    /// @param format Requested encoding; kDer or kPem.
    /// @return The concatenated bytes, kInvalidArgument for any other format, or the first encoding error.
    [[nodiscard]] score::crypto::Expected<std::vector<std::uint8_t>, common::DaemonErrorCode> EncodeChain(
        const std::vector<CertObject::Sptr>& chain,
        score::crypto::FormatType format) const;

    /// @brief Pack CRL metadata entries in order, each in the CrlMetadataWireLayout encoding.
    /// @param metadata Entries to pack.
    /// @return kEntrySize bytes per entry; empty when @p metadata is empty.
    [[nodiscard]] static std::vector<std::uint8_t> PackCrlMetadata(
        const std::vector<score::crypto::CrlMetadata>& metadata);

  private:
    provider::cert_management::ICertParser::Sptr m_parser;  ///< Encodes certificates; never null.
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CONTEXT_VERIFICATION_RESULT_ENCODER_HPP

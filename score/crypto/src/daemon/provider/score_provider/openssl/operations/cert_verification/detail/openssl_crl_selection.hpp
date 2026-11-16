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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_CERT_VERIFICATION_DETAIL_OPENSSL_CRL_SELECTION_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_CERT_VERIFICATION_DETAIL_OPENSSL_CRL_SELECTION_HPP

#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/detail/openssl_cert_utils.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/cert_verification/detail/openssl_x509_utils.hpp"

#include <openssl/x509.h>

#include <vector>

namespace score::crypto::daemon::provider::openssl::detail
{

/// A parsed CRL together with its metadata; the metadata includes the fingerprint of the issuing certificate.
struct ParsedCrl
{
    UniqueX509Crl value;
    score::crypto::CrlMetadata metadata;
};

/// @brief Parses CRLs and keeps one per issuer.
///
/// Per issuer, the CRL with the highest CRL number wins, and a numbered CRL beats an unnumbered one; equal
/// numbers (including both absent) fall back to the latest thisUpdate. CRLs that fail to parse, or whose
/// issuer is not among @p issuer_candidates, are skipped.
/// The order of the returned CRLs is unspecified.
///
/// @param crls Raw DER or PEM CRLs to consider.
/// @param issuer_candidates Certificates that may have issued the CRLs (leaf, chain, additional, trusted).
/// @return The selected CRLs, or an error if an issuer fingerprint or CRL digest cannot be computed.
[[nodiscard]] Expected<std::vector<ParsedCrl>, common::DaemonErrorCode> SelectCrlsPerIssuer(
    const std::vector<::score::crypto::daemon::cert_management::CrlEntry>& crls,
    const std::vector<CertSptr>& issuer_candidates);

/// @brief Packs the metadata of the selected CRLs that apply to a verified path.
///
/// A CRL applies when its issuer matches the issuer name of a certificate in @p chain. Each entry is
/// encoded with CrlMetadataWireLayout.
///
/// @param selected CRLs returned by SelectCrlsPerIssuer().
/// @param chain Certificate path from the verification context; may be null.
/// @return Concatenated wire entries, empty if @p chain is null or no CRL applies.
[[nodiscard]] common::OwnedBuffer EncodeSelectedCrlMetadata(const std::vector<ParsedCrl>& selected,
                                                            STACK_OF(X509) * chain);

}  // namespace score::crypto::daemon::provider::openssl::detail

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_CERT_VERIFICATION_DETAIL_OPENSSL_CRL_SELECTION_HPP

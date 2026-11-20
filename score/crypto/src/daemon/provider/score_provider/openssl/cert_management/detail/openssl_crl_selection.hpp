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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_CERT_MANAGEMENT_DETAIL_OPENSSL_CRL_SELECTION_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_CERT_MANAGEMENT_DETAIL_OPENSSL_CRL_SELECTION_HPP

#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/cert_management/detail/openssl_x509_utils.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/detail/openssl_cert_utils.hpp"

#include <openssl/x509.h>

#include <memory>
#include <vector>

namespace score::crypto::daemon::provider::openssl::detail
{

/// A parsed CRL together with the metadata derived from its bytes.
struct ParsedCrl
{
    UniqueX509Crl value;
    score::crypto::CrlMetadata metadata;
};

/// @brief Parses CRLs and keeps one per issuer.
///
/// Each CRL is parsed from its own bytes and format. Its issuer is the candidate whose subject matches the CRL issuer
/// name and whose key verifies the CRL signature. When the caller supplied metadata for a CRL, its fingerprint must
/// match the digest of the parsed CRL; a mismatch means the metadata does not describe these bytes, and the CRL is
/// skipped.
///
/// Per issuer, the CRL with the highest CRL number wins, and a numbered CRL beats an unnumbered one. Equal numbers
/// fall back to the latest thisUpdate, and a full tie keeps the earlier CRL. CRLs that fail to parse, that no
/// candidate issuer signed, or whose metadata does not match are skipped. The returned CRLs keep the order of @p crls.
///
/// @param crls CRLs to consider; entries must not be null.
/// @param issuer_candidates Certificates that may have issued the CRLs (leaf, untrusted, trust anchors).
/// @return The selected CRLs, or an error if an issuer fingerprint or CRL digest cannot be computed.
[[nodiscard]] score::crypto::Expected<std::vector<ParsedCrl>, common::DaemonErrorCode> SelectCrlsPerIssuer(
    const std::vector<std::shared_ptr<const ::score::crypto::daemon::cert_management::CrlData>>& crls,
    const std::vector<CertSptr>& issuer_candidates);

/// @brief Returns the metadata of the selected CRLs that apply to a verified path.
///
/// A CRL applies when its issuer name matches the issuer name of a certificate in @p chain.
///
/// @param selected CRLs returned by SelectCrlsPerIssuer().
/// @param chain Certificate path from the verification context; may be null.
/// @return Metadata in the order of @p selected, empty if @p chain is null or no CRL applies.
[[nodiscard]] std::vector<score::crypto::CrlMetadata> AppliedCrlMetadata(const std::vector<ParsedCrl>& selected,
                                                                         STACK_OF(X509) * chain);

}  // namespace score::crypto::daemon::provider::openssl::detail

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_CERT_MANAGEMENT_DETAIL_OPENSSL_CRL_SELECTION_HPP

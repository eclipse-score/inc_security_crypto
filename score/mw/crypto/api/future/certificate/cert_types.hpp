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

#ifndef SCORE_MW_CRYPTO_API_CERTIFICATE_CERT_TYPES_HPP
#define SCORE_MW_CRYPTO_API_CERTIFICATE_CERT_TYPES_HPP

#include "score/mw/crypto/api/common/types.hpp"

#include <cstdint>

namespace score
{
namespace mw
{
namespace crypto
{

/// @brief Result of a certificate verification operation.
enum class CertVerifyResult : uint8_t
{
    kValid,             ///< Certificate is valid and trusted
    kExpired,           ///< Certificate has expired
    kNotYetValid,       ///< Certificate is not yet valid (future notBefore)
    kRevoked,           ///< Certificate has been revoked
    kNoRootFound,       ///< Root CA is not in the trust store
    kChainIncomplete,   ///< Intermediate certificate missing
    kSignatureInvalid,  ///< Signature verification failed
    kInvalidPurpose,    ///< Key usage or extended key usage mismatch
    kUnknownAlgorithm,  ///< Unsupported or unknown algorithm in certificate
    kUnknownError       ///< Unspecified verification failure
};

/// @brief Status of an OCSP response.
enum class OcspStatus : uint8_t
{
    kGood,     ///< Certificate is not revoked
    kRevoked,  ///< Certificate has been revoked
    kUnknown,  ///< Responder does not know the certificate
    kError     ///< OCSP response could not be parsed or verified
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_CERTIFICATE_CERT_TYPES_HPP

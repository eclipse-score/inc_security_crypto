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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_CERT_VERIFICATION_DETAIL_OPENSSL_X509_UTILS_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_CERT_VERIFICATION_DETAIL_OPENSSL_X509_UTILS_HPP

#include "score/crypto/src/daemon/cert_management/interfaces/cert_object.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/detail/openssl_cert_utils.hpp"

#include <openssl/x509.h>

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace score::crypto::daemon::provider::openssl::detail
{

using CertObject = ::score::crypto::daemon::cert_management::CertObject;
using CertSptr = std::shared_ptr<CertObject>;

struct X509StoreDeleter
{
    void operator()(X509_STORE* p) const noexcept
    {
        X509_STORE_free(p);
    }
};
using UniqueX509Store = std::unique_ptr<X509_STORE, X509StoreDeleter>;

struct X509StoreCtxDeleter
{
    void operator()(X509_STORE_CTX* p) const noexcept
    {
        X509_STORE_CTX_free(p);
    }
};
using UniqueX509StoreCtx = std::unique_ptr<X509_STORE_CTX, X509StoreCtxDeleter>;

struct StackX509Deleter
{
    void operator()(STACK_OF(X509) * p) const noexcept
    {
        sk_X509_pop_free(p, X509_free);
    }
};
using UniqueStackX509 = std::unique_ptr<STACK_OF(X509), StackX509Deleter>;

/// @brief Parses a certificate object into an OpenSSL X509.
///
/// @param cert Certificate holding raw DER or PEM bytes.
/// @return The parsed certificate, or nullptr if the bytes are empty or cannot be parsed.
UniqueX509 CertToX509(const CertObject& cert);

/// @brief Computes the SHA-256 fingerprint of a certificate.
///
/// @param x Certificate to fingerprint; must not be null.
/// @return The 32 raw digest bytes (not hex-encoded) in a string, or an empty string on failure.
std::string FingerprintOf(const X509* x);

/// @brief Builds a fingerprint-to-certificate index over all verification inputs.
///
/// Used to map a chain built by OpenSSL back to the caller's certificate objects.
/// Null entries and certificates without a fingerprint are skipped; when a fingerprint
/// occurs more than once, the first certificate inserted (leaf, chain, additional, trusted) wins.
///
/// @param leaf Leaf certificate.
/// @param chain Client-supplied chain certificates.
/// @param additional Client-supplied untrusted intermediates.
/// @param trusted Trust anchors.
/// @return Map from raw SHA-256 fingerprint bytes to the certificate.
std::unordered_map<std::string, CertSptr> BuildFingerprintIndex(const CertSptr& leaf,
                                                                const std::vector<CertSptr>& chain,
                                                                const std::vector<CertSptr>& additional,
                                                                const std::vector<CertSptr>& trusted);

}  // namespace score::crypto::daemon::provider::openssl::detail

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_CERT_VERIFICATION_DETAIL_OPENSSL_X509_UTILS_HPP

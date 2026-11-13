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

#include "score/crypto/src/daemon/provider/score_provider/openssl/cert_management/detail/openssl_x509_utils.hpp"

#include <openssl/x509.h>

#include <cstdint>

namespace score::crypto::daemon::provider::openssl::detail
{

UniqueX509 CertToX509(const CertObject& cert)
{
    const auto raw = cert.GetRawBytes();
    return ParseX509(raw.data(), raw.size(), cert.GetFormat());
}

std::string FingerprintOf(const X509* x)
{
    Sha256Digest digest{};
    if (!ComputeSha256(x, digest))
        return {};
    return std::string(reinterpret_cast<const char*>(digest.data()), digest.size());
}

std::unordered_map<std::string, CertSptr> BuildFingerprintIndex(const CertSptr& leaf,
                                                                const std::vector<CertSptr>& untrusted,
                                                                const std::vector<CertSptr>& trust_anchors)
{
    std::unordered_map<std::string, CertSptr> index;
    const auto insert = [&index](const CertSptr& certificate) {
        if (!certificate)
            return;
        const auto fingerprint = certificate->GetFingerprint();
        if (fingerprint.empty())
            return;
        index.emplace(std::string(reinterpret_cast<const char*>(fingerprint.data()), fingerprint.size()), certificate);
    };

    insert(leaf);
    for (const auto& certificate : untrusted)
        insert(certificate);
    for (const auto& certificate : trust_anchors)
        insert(certificate);
    return index;
}

}  // namespace score::crypto::daemon::provider::openssl::detail

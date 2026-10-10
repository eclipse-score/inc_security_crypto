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

#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/cert_verification/detail/openssl_x509_utils.hpp"

#include <openssl/x509.h>

#include <cstdint>

namespace score::crypto::daemon::provider::openssl::detail
{

UniqueX509 CertToX509(const CertObject& cert)
{
    const auto& raw = cert.GetRawBytes();
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
                                                                const std::vector<CertSptr>& chain,
                                                                const std::vector<CertSptr>& additional,
                                                                const std::vector<CertSptr>& trusted)
{
    std::unordered_map<std::string, CertSptr> idx;
    auto insert = [&](const CertSptr& c) {
        if (!c)
            return;
        const auto fp = c->GetFingerprint();  // span<const uint8_t>
        if (!fp.empty())
            idx.emplace(std::string(reinterpret_cast<const char*>(fp.data()), fp.size()), c);
    };
    insert(leaf);
    for (const auto& c : chain)
        insert(c);
    for (const auto& c : additional)
        insert(c);
    for (const auto& c : trusted)
        insert(c);
    return idx;
}

}  // namespace score::crypto::daemon::provider::openssl::detail

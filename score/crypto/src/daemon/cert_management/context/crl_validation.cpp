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

#include "score/crypto/src/daemon/cert_management/context/crl_validation.hpp"

#include "score/mw/log/logging.h"

#include <cstdint>
#include <string_view>

namespace score::crypto::daemon::cert_management
{

namespace
{

constexpr std::string_view kLogPrefix{"[CRL_VALIDATION] "};

}  // namespace

score::crypto::Expected<CrlData, common::DaemonErrorCode> ValidateCrlAgainstIssuer(
    provider::cert_management::ICertParser& parser,
    const CertObject& issuer,
    score::crypto::span<const std::uint8_t> crl_bytes,
    score::crypto::FormatType crl_format)
{
    if (crl_format != score::crypto::FormatType::kDer && crl_format != score::crypto::FormatType::kPem)
    {
        score::mw::log::LogError() << kLogPrefix << "CRL format is neither DER nor PEM";
        return score::crypto::make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }

    CrlData crl;
    crl.bytes.assign(crl_bytes.begin(), crl_bytes.end());
    crl.format = crl_format;

    const auto issuer_bytes = issuer.GetRawBytes();
    auto metadata = parser.ValidateCrl(crl, issuer_bytes.data(), issuer_bytes.size(), issuer.GetFormat());
    if (!metadata.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "CRL validation failed";
        return score::crypto::make_unexpected(metadata.error());
    }
    crl.metadata = metadata.value();
    return crl;
}

}  // namespace score::crypto::daemon::cert_management

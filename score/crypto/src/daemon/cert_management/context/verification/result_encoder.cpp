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

#include "score/crypto/src/daemon/cert_management/context/verification/result_encoder.hpp"

#include "score/crypto/src/daemon/cert_management/interfaces/crl_metadata_wire_layout.hpp"
#include "score/mw/log/logging.h"

#include <array>
#include <string_view>
#include <utility>

namespace score::crypto::daemon::cert_management
{

namespace
{

constexpr std::string_view kLogPrefix{"[CERT_VERIFY_OUT] "};

bool IsExportFormat(score::crypto::FormatType format)
{
    return format == score::crypto::FormatType::kDer || format == score::crypto::FormatType::kPem;
}

}  // namespace

VerifiedResultEncoder::VerifiedResultEncoder(provider::cert_management::ICertParser::Sptr parser)
    : m_parser{std::move(parser)}
{
}

score::crypto::Expected<std::vector<std::uint8_t>, common::DaemonErrorCode> VerifiedResultEncoder::EncodeCertificate(
    const CertObject& certificate,
    score::crypto::FormatType format) const
{
    if (!IsExportFormat(format))
    {
        score::mw::log::LogError() << kLogPrefix << "Unsupported export format";
        return score::crypto::make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }
    return m_parser->EncodeCertificate(certificate, format);
}

score::crypto::Expected<std::vector<std::uint8_t>, common::DaemonErrorCode> VerifiedResultEncoder::EncodeChain(
    const std::vector<CertObject::Sptr>& chain,
    score::crypto::FormatType format) const
{
    if (!IsExportFormat(format))
    {
        score::mw::log::LogError() << kLogPrefix << "Unsupported export format";
        return score::crypto::make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }

    std::vector<std::uint8_t> output;
    for (const auto& certificate : chain)
    {
        if (!certificate)
        {
            return score::crypto::make_unexpected(common::DaemonErrorCode::kInternalError);
        }
        auto encoded = EncodeCertificate(*certificate, format);
        if (!encoded.has_value())
        {
            return score::crypto::make_unexpected(encoded.error());
        }
        output.insert(output.end(), encoded.value().begin(), encoded.value().end());
    }
    return output;
}

std::vector<std::uint8_t> VerifiedResultEncoder::PackCrlMetadata(
    const std::vector<score::crypto::CrlMetadata>& metadata)
{
    std::vector<std::uint8_t> packed;
    packed.reserve(metadata.size() * CrlMetadataWireLayout::kEntrySize);
    for (const auto& entry : metadata)
    {
        std::array<std::uint8_t, CrlMetadataWireLayout::kEntrySize> encoded{};
        CrlMetadataWireLayout::Encode(entry, encoded);
        packed.insert(packed.end(), encoded.begin(), encoded.end());
    }
    return packed;
}

}  // namespace score::crypto::daemon::cert_management

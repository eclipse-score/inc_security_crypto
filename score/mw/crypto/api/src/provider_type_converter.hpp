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

#ifndef SCORE_MW_CRYPTO_API_SRC_PROVIDER_TYPE_CONVERTER_HPP
#define SCORE_MW_CRYPTO_API_SRC_PROVIDER_TYPE_CONVERTER_HPP

#include "score/mw/crypto/api/common/types.hpp"

#include <cstdint>

namespace score
{
namespace mw
{
namespace crypto
{

namespace ProviderTypeConverter
{

/// @brief Encode a client-side ProviderType preference as its IPC wire value.
///
/// The wire protocol carries the raw uint8_t representation of the ProviderType
/// enumerator.  The daemon decodes this with its own FromWireProviderType()
/// function and maps it to its internal CryptoProviderType classification.
///
/// This function must NOT depend on daemon-internal headers — the client library
/// and the daemon are independently deployable components.
///
/// Wire encoding (matches ProviderType enumerator positions):
///   0 = kDefault
///   1 = kHardware
///   2 = kSoftware
///   3 = kHardwarePreferred
///   4 = kSoftwarePreferred
inline constexpr std::uint8_t ToWireValue(ProviderType api_type) noexcept
{
    return static_cast<std::uint8_t>(api_type);
}

}  // namespace ProviderTypeConverter

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_SRC_PROVIDER_TYPE_CONVERTER_HPP

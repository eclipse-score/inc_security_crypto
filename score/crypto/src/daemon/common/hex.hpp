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

#ifndef SCORE_CRYPTO_SRC_DAEMON_COMMON_HEX_HPP
#define SCORE_CRYPTO_SRC_DAEMON_COMMON_HEX_HPP

#include "score/crypto/src/common/types.hpp"

#include <cctype>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace score::crypto::daemon::common
{

[[nodiscard]] inline std::string EncodeHex(score::crypto::span<const uint8_t> bytes)
{
    static constexpr char kHex[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2U);
    for (const auto byte : bytes)
    {
        result.push_back(kHex[(byte >> 4U) & 0x0FU]);
        result.push_back(kHex[byte & 0x0FU]);
    }
    return result;
}

[[nodiscard]] inline std::optional<std::vector<uint8_t>> DecodeHex(const std::string& value)
{
    if ((value.size() % 2U) != 0U)
        return std::nullopt;

    const auto nibble = [](char c) -> int {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return c >= '0' && c <= '9' ? c - '0' : (c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1);
    };
    std::vector<uint8_t> result(value.size() / 2U);
    for (std::size_t i = 0U; i < result.size(); ++i)
    {
        const int high = nibble(value[2U * i]);
        const int low = nibble(value[2U * i + 1U]);
        if (high < 0 || low < 0)
            return std::nullopt;
        result[i] = static_cast<uint8_t>((high << 4) | low);
    }
    return result;
}

}  // namespace score::crypto::daemon::common

#endif  // SCORE_CRYPTO_SRC_DAEMON_COMMON_HEX_HPP

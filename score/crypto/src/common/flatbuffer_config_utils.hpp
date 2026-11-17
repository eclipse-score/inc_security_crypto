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

#ifndef SCORE_CRYPTO_SRC_COMMON_FLATBUFFER_CONFIG_UTILS_HPP
#define SCORE_CRYPTO_SRC_COMMON_FLATBUFFER_CONFIG_UTILS_HPP

#include <flatbuffers/string.h>

#include <algorithm>
#include <cctype>
#include <string_view>

namespace score::crypto::config_utils
{

/// Return true when a FlatBuffers string contains non-whitespace text and no
/// control characters.
inline bool HasText(const ::flatbuffers::String* value)
{
    if ((value == nullptr) || value->empty())
    {
        return false;
    }

    const std::string_view text{value->c_str(), value->size()};
    if (text.find_first_not_of(" \t\r\n") == std::string_view::npos)
    {
        return false;
    }

    return std::none_of(text.begin(), text.end(), [](const char character) {
        return std::iscntrl(static_cast<unsigned char>(character)) != 0;
    });
}

}  // namespace score::crypto::config_utils

#endif  // SCORE_CRYPTO_SRC_COMMON_FLATBUFFER_CONFIG_UTILS_HPP

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

#ifndef SCORE_CRYPTO_SRC_DAEMON_KEY_MANAGEMENT_DETAIL_SLOT_INFO_BUILDER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_KEY_MANAGEMENT_DETAIL_SLOT_INFO_BUILDER_HPP

#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/api/types/key.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_slot_config.hpp"

#include <cstddef>
#include <string_view>

namespace score::crypto::daemon::key_management::detail
{

/// @brief Builds the client-facing KeySlotInfo from the slot config and its current state.
///
/// The algorithm is the slot's configured constraint and is reported for empty
/// slots too, so a client can tell which key type the slot accepts.
/// provider_ids[0] is the primary provider; the rest are reported as compatible
/// providers (truncated to KeySlotInfo::kMaxCompatibleProviders).
inline score::crypto::KeySlotInfo BuildKeySlotInfo(const KeySlotConfig& slot,
                                                   score::crypto::KeySlotState state) noexcept
{
    score::crypto::KeySlotInfo info{};
    info.state = state;
    info.algorithm = std::string_view{slot.algorithm};
    info.permitted_operations = slot.allowed_operations;
    if (!slot.provider_ids.empty())
    {
        info.primary_provider = slot.provider_ids.front();
        for (std::size_t i = 1U;
             (i < slot.provider_ids.size()) && (info.compatible_provider_count < info.compatible_providers.size());
             ++i)
        {
            info.compatible_providers.at(info.compatible_provider_count) = slot.provider_ids[i];
            ++info.compatible_provider_count;
        }
    }
    return info;
}

}  // namespace score::crypto::daemon::key_management::detail

#endif  // SCORE_CRYPTO_SRC_DAEMON_KEY_MANAGEMENT_DETAIL_SLOT_INFO_BUILDER_HPP

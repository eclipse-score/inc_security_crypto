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

#include "score/crypto/src/api/common/types.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_slot_config.hpp"

namespace score::crypto::daemon::key_management::detail
{

inline score::crypto::KeySlotInfo BuildKeySlotInfo(const KeySlotConfig& slot,
                                                   score::crypto::KeySlotState state,
                                                   uint16_t primary_provider = 0U) noexcept
{
    score::crypto::KeySlotInfo info{};
    info.state = state;
    info.algorithm = (state == score::crypto::KeySlotState::kOccupied) ? slot.algorithm : common::AlgorithmId{};
    info.primary_provider = primary_provider;
    info.permitted_operations = slot.allowed_operations;
    info.compatible_provider_count = 0U;
    return info;
}

}  // namespace score::crypto::daemon::key_management::detail

#endif  // SCORE_CRYPTO_SRC_DAEMON_KEY_MANAGEMENT_DETAIL_SLOT_INFO_BUILDER_HPP

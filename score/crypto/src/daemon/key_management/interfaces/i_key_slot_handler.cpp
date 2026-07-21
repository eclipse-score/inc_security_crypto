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

#include "score/crypto/daemon/key_management/interfaces/i_key_slot_handler.hpp"

#include "score/crypto/daemon/common/daemon_error.hpp"

namespace score::crypto::daemon::key_management
{

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> IKeySlotHandler::StoreKey(
    const KeySlotConfig& /*slot*/,
    IKeyHandler& /*handler*/)
{
    return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> IKeySlotHandler::ClearSlot(
    const KeySlotConfig& /*slot*/)
{
    return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
}

}  // namespace score::crypto::daemon::key_management

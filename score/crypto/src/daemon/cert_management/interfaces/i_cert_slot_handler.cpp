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

#include "score/crypto/src/daemon/cert_management/interfaces/i_cert_slot_handler.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"

namespace score::crypto::daemon::cert_management
{

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
ICertSlotHandler::StoreCertificate(const CertSlotConfig& /*slot*/, const CertObject& /*cert*/)
{
    return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> ICertSlotHandler::ClearSlot(
    const CertSlotConfig& /*slot*/)
{
    return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
}

score::crypto::Expected<std::vector<uint8_t>, score::crypto::daemon::common::DaemonErrorCode> ICertSlotHandler::LoadCrl(
    const CertSlotConfig& /*slot*/)
{
    return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> ICertSlotHandler::StoreCrl(
    const CertSlotConfig& /*slot*/,
    score::crypto::span<const uint8_t> /*crl_data*/,
    score::crypto::FormatType /*format*/)
{
    return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> ICertSlotHandler::ClearCrl(
    const CertSlotConfig& /*slot*/)
{
    return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
}

score::crypto::Expected<int64_t, score::crypto::daemon::common::DaemonErrorCode> ICertSlotHandler::GetCrlNextUpdate(
    const CertSlotConfig& /*slot*/)
{
    return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
}

score::crypto::FormatType ICertSlotHandler::GetCrlFormat(const CertSlotConfig& /*slot*/)
{
    return score::crypto::FormatType::kDer;
}

}  // namespace score::crypto::daemon::cert_management

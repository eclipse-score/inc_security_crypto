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

using DaemonError = score::crypto::daemon::common::DaemonErrorCode;

const CertSlotConfig& ICertSlotHandler::GetConfig() const noexcept
{
    return m_config;
}

score::crypto::Expected<std::monostate, DaemonError> ICertSlotHandler::StoreCertificate(const CertObject& /*cert*/)
{
    return score::crypto::make_unexpected(DaemonError::kUnsupportedOperation);
}

score::crypto::Expected<std::monostate, DaemonError> ICertSlotHandler::ClearSlot()
{
    return score::crypto::make_unexpected(DaemonError::kUnsupportedOperation);
}

score::crypto::Expected<std::monostate, DaemonError> ICertSlotHandler::StoreCrl(const CrlData& /*crl*/)
{
    return score::crypto::make_unexpected(DaemonError::kUnsupportedOperation);
}

score::crypto::Expected<std::monostate, DaemonError> ICertSlotHandler::ClearCrl()
{
    return score::crypto::make_unexpected(DaemonError::kUnsupportedOperation);
}

score::crypto::Expected<std::optional<score::crypto::CrlMetadata>, DaemonError> ICertSlotHandler::GetCrlMetadata()
{
    return std::optional<score::crypto::CrlMetadata>{};
}

score::crypto::Expected<std::optional<CrlData>, DaemonError> ICertSlotHandler::LoadCrlData()
{
    return score::crypto::make_unexpected(DaemonError::kUnsupportedOperation);
}

}  // namespace score::crypto::daemon::cert_management
